use clap::{Parser, Subcommand};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use globset::{Glob, GlobSet, GlobSetBuilder};
use quick_xml::de::from_str;
use quick_xml::se::to_string;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use russh::client::{Config, Handler};
use russh_keys::key;

#[derive(Parser, Debug)]
#[command(name = "brass", author, version, about = "Brass Control")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

struct ClientHandler;

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init,
    Add {
        #[arg(required = true)]
        path: PathBuf,
    },
    Commit {
        #[arg(short, long)]
        message: String,
    },
    Status,
    Checkout {
        #[arg(required = true)]
        target: String,
    },
    Diff {
        path: Option<PathBuf>,
    },
    CatObject {
        #[arg(required = true)]
        hash: String,
    },
    Tag {
        #[command(subcommand)]
        command: TagCommands,
    },
    Gc,
    Pack,
    Leaf {
        #[command(subcommand)]
        command: LeafCommands,
    },
    Log {
        #[arg(short = 'n', long)]
        limit: Option<usize>,
    },
    Blame {
        #[arg(required = true)]
        path: PathBuf,
    },
    Push {
        #[arg(required = true)]
        remote: String,
        #[arg(required = true)]
        ref_name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum TagCommands {
    Create {
        #[arg(required = true)]
        name: String,
        target: Option<String>,
    },
    List,
    Delete {
        #[arg(required = true)]
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum LeafCommands {
    Create {
        #[arg(required = true)]
        name: String,
    },
    List,
    Merge {
        #[arg(required = true)]
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMode {
    Regular,
    Executable,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: FileMode,
    pub name: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub email: String,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree_hash: String,
    pub parent_hashes: Vec<String>,
    pub author: Signature,
    pub committer: Signature,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrassObject {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: PathBuf,
    pub hash: String,
    pub mode: FileMode,
    pub modified_at: SystemTime,
    pub file_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Index {
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "brass_config")]
pub struct BrassConfig {
    pub user_name: String,
    pub user_email: String,
    pub default_branch: String,
    pub is_admin: bool,
}

impl Default for BrassConfig {
    fn default() -> Self {
        Self {
            user_name: String::from("Anonymous"),
            user_email: String::from("user@localhost"),
            default_branch: String::from("main"),
                is_admin: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRule {
    pub user: String,
    pub path_pattern: String,
    pub access: AccessLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename = "brass_acl")]
pub struct AclConfig {
    pub rules: Vec<AccessRule>,
}

impl AclConfig {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let xml_str = to_string(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, xml_str)
    }

    pub fn can_write(&self, user: &str, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for rule in &self.rules {
            if rule.user == user || rule.user == "*" {
                let clean_pattern = rule.path_pattern.trim_end_matches("/**").trim_end_matches("/*");
                if path_str.starts_with(clean_pattern) && rule.access == AccessLevel::ReadOnly {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    Branch(String),
    Leaf { user: String, name: String },
    Tag(String),
}

impl RefKind {
    pub fn to_path_suffix(&self) -> PathBuf {
        match self {
            RefKind::Branch(name) => PathBuf::from("refs").join("heads").join(name),
            RefKind::Leaf { user, name } => PathBuf::from("refs").join("leaves").join(user).join(name),
            RefKind::Tag(name) => PathBuf::from("refs").join("tags").join(name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafMergeResult {
    Success(String),
    PermissionDenied { user: String, forbidden_path: PathBuf },
    ConflictInLeaf { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeChunk {
    Clean(Vec<String>),
    Conflict { target: Vec<String>, leaf: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Keep(String),
    Insert(String),
    Delete(String),
}

#[derive(Debug, Clone)]
pub struct BrassIgnore {
    pub raw_patterns: Vec<String>,
    pub glob_set: GlobSet,
}

impl Default for BrassIgnore {
    fn default() -> Self {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new(".brass_control/**").unwrap());
        builder.add(Glob::new("**/.brass_control/**").unwrap());

        Self {
            raw_patterns: vec![".brass_control/**".to_string()],
            glob_set: builder.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }
}

impl BrassIgnore {
    pub fn load(path: &Path) -> Self {
        let mut builder = GlobSetBuilder::new();
        let mut raw_patterns = Vec::new();
        let default_rules = [".brass_control/**", "**/.brass_control/**", ".brass_control_ignore"];

        for rule in &default_rules {
            if let Ok(glob) = Glob::new(rule) {
                builder.add(glob);
                raw_patterns.push(rule.to_string());
            }
        }

        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    let normalized_pattern = if trimmed.ends_with('/') {
                        format!("{}**", trimmed)
                    } else if !trimmed.contains('/') {
                        format!("**/{}", trimmed)
                    } else {
                        trimmed.trim_start_matches('/').to_string()
                    };

                    if let Ok(glob) = Glob::new(&normalized_pattern) {
                        builder.add(glob);
                        raw_patterns.push(trimmed.to_string());
                    }
                }
            }
        }

        Self {
            raw_patterns,
            glob_set: builder.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        self.glob_set.is_match(path)
    }
}

#[derive(Debug, Clone)]
pub struct Repository {
    pub worktree: PathBuf,
    pub brass_dir: PathBuf,
    pub ignore: BrassIgnore,
    pub config: BrassConfig,
    pub acl: AclConfig,
}

impl Repository {
    pub fn init(path: &Path) -> std::io::Result<Self> {
        let brass_dir = path.join(".brass_control");

        fs::create_dir_all(brass_dir.join("objects"))?;
        fs::create_dir_all(brass_dir.join("packs"))?;
        fs::create_dir_all(brass_dir.join("refs").join("heads"))?;
        fs::create_dir_all(brass_dir.join("refs").join("leaves"))?;
        fs::create_dir_all(brass_dir.join("refs").join("tags"))?;

        let head_path = brass_dir.join("HEAD");
        if !head_path.exists() {
            fs::write(head_path, "ref: refs/heads/main\n")?;
        }

        let config_path = brass_dir.join(".brass_config.xml");
        let config = if config_path.exists() {
            BrassConfig::load(&config_path)?
        } else {
            let default_cfg = BrassConfig::default();
            default_cfg.save(&config_path)?;
            default_cfg
        };

        let acl_path = brass_dir.join(".brass_acl.xml");
        let acl = if acl_path.exists() {
            AclConfig::load(&acl_path)?
        } else {
            let default_acl = AclConfig::default();
            default_acl.save(&acl_path)?;
            default_acl
        };

        let ignore = BrassIgnore::load(&path.join(".brass_control_ignore"));

        Ok(Self {
            worktree: path.to_path_buf(),
           brass_dir,
           ignore,
           config,
           acl,
        })
    }

    pub fn write_object(&self, object: &BrassObject) -> std::io::Result<String> {
        let (hash, uncompressed_data) = object.serialize();
        let obj_dir = self.brass_dir.join("objects").join(&hash[..2]);
        fs::create_dir_all(&obj_dir)?;

        let obj_path = obj_dir.join(&hash[2..]);
        if !obj_path.exists() {
            let file = File::create(obj_path)?;
            let mut encoder = ZlibEncoder::new(file, Compression::default());
            encoder.write_all(&uncompressed_data)?;
        }

        Ok(hash)
    }

    pub fn read_object(&self, hash: &str) -> std::io::Result<BrassObject> {
        let obj_path = self.brass_dir.join("objects").join(&hash[..2]).join(&hash[2..]);

        let decompressed_data = if obj_path.exists() {
            let file = File::open(obj_path)?;
            let mut decoder = ZlibDecoder::new(file);
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf)?;
            buf
        } else if let Some(buf) = self.read_object_from_packs(hash)? {
            buf
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("Nie znaleziono obiektu: {}", hash)));
        };

        let null_pos = decompressed_data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Brak nagłówka"))?;

        let header = String::from_utf8_lossy(&decompressed_data[..null_pos]);
        let payload = &decompressed_data[null_pos + 1..];
        let mut parts = header.split_whitespace();
        let obj_type = parts.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Brak typu"))?;

        match obj_type {
            "blob" => Ok(BrassObject::Blob(Blob { data: payload.to_vec() })),
            "tree" => Ok(BrassObject::Tree(Tree::deserialize_payload(payload)?)),
            "commit" => Ok(BrassObject::Commit(Commit::deserialize_payload(payload)?)),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Nieznany typ")),
        }
    }

    fn read_object_from_packs(&self, hash: &str) -> std::io::Result<Option<Vec<u8>>> {
        let packs_dir = self.brass_dir.join("packs");
        if !packs_dir.exists() {
            return Ok(None);
        }

        for entry in fs::read_dir(packs_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("idx") {
                let index_content = fs::read_to_string(&path)?;
                for line in index_content.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() == 3 && parts[0] == hash {
                        let offset: u64 = parts[1].parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        let len: usize = parts[2].parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                        let pack_path = path.with_extension("pack");
                        let mut pack_file = File::open(pack_path)?;
                        pack_file.seek(SeekFrom::Start(offset))?;

                        let mut compressed_buf = vec![0u8; len];
                        pack_file.read_exact(&mut compressed_buf)?;

                        let mut decoder = ZlibDecoder::new(&compressed_buf[..]);
                        let mut decompressed = Vec::new();
                        decoder.read_to_end(&mut decompressed)?;
                        return Ok(Some(decompressed));
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn add(&self, relative_path: &Path, index: &mut Index) -> std::io::Result<()> {
        if self.ignore.is_ignored(relative_path) {
            return Ok(());
        }

        if !self.acl.can_write(&self.config.user_name, relative_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Brak uprawnień zapisu (ReadOnly) dla '{}' na {:?}", self.config.user_name, relative_path),
            ));
        }

        let full_path = self.worktree.join(relative_path);
        let metadata = fs::metadata(&full_path)?;

        if metadata.is_dir() {
            let mut queue = VecDeque::new();
            queue.push_back(relative_path.to_path_buf());

            while let Some(current_rel) = queue.pop_front() {
                let current_full = self.worktree.join(&current_rel);
                for entry in fs::read_dir(current_full)? {
                    let entry = entry?;
                    let child_rel = current_rel.join(entry.file_name());

                    if self.ignore.is_ignored(&child_rel) {
                        continue;
                    }

                    let ft = entry.file_type()?;
                    if ft.is_dir() {
                        queue.push_back(child_rel);
                    } else if ft.is_file() {
                        self.add_single_file(&child_rel, index)?;
                    }
                }
            }
            Ok(())
        } else {
            self.add_single_file(relative_path, index)
        }
    }

    fn add_single_file(&self, relative_path: &Path, index: &mut Index) -> std::io::Result<()> {
        let full_path = self.worktree.join(relative_path);
        let data = fs::read(&full_path)?;
        let metadata = fs::metadata(&full_path)?;

        let blob_hash = self.write_object(&BrassObject::Blob(Blob { data }))?;
        let mode = if metadata.permissions().readonly() {
            FileMode::Regular
        } else {
            FileMode::Executable
        };

        let entry = IndexEntry {
            path: relative_path.to_path_buf(),
            hash: blob_hash,
            mode,
            modified_at: metadata.modified()?,
            file_size: metadata.len(),
        };

        if let Some(existing) = index.entries.iter_mut().find(|e| e.path == relative_path) {
            *existing = entry;
        } else {
            index.entries.push(entry);
        }

        Ok(())
    }

    pub fn commit(&self, message: String, author: Signature, index: &Index) -> std::io::Result<String> {
        let mut tree_entries = Vec::new();
        for entry in &index.entries {
            tree_entries.push(TreeEntry {
                mode: entry.mode,
                name: entry.path.to_string_lossy().to_string(),
                              hash: entry.hash.clone(),
            });
        }

        let tree_hash = self.write_object(&BrassObject::Tree(Tree { entries: tree_entries }))?;
        let parent_hashes = self.get_head_commit_hash().map(|h| vec![h]).unwrap_or_default();

        let commit_hash = self.write_object(&BrassObject::Commit(Commit {
            tree_hash,
            parent_hashes,
            author: author.clone(),
                                                                 committer: author,
                                                                 message,
        }))?;

        self.update_head_target(&commit_hash)?;
        Ok(commit_hash)
    }

    pub fn checkout(&self, target: &str) -> std::io::Result<()> {
        let target_ref_path = if target.starts_with("tags/") {
            self.brass_dir.join("refs").join(target)
        } else if target.contains('/') {
            self.brass_dir.join("refs").join("leaves").join(target)
        } else {
            let branch_path = self.brass_dir.join("refs").join("heads").join(target);
            let tag_path = self.brass_dir.join("refs").join("tags").join(target);

            if branch_path.exists() {
                branch_path
            } else if tag_path.exists() {
                tag_path
            } else {
                PathBuf::new()
            }
        };

        let commit_hash = if target_ref_path.exists() {
            fs::read_to_string(&target_ref_path)?.trim().to_string()
        } else if self.read_object(target).is_ok() {
            target.to_string()
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Cel checkout nie istnieje"));
        };

        let target_files = self.flatten_tree_from_commit(&commit_hash)?;
        let mut new_index = Index::default();

        for (rel_path, hash) in &target_files {
            if let Ok(BrassObject::Blob(blob)) = self.read_object(hash) {
                let full_path = self.worktree.join(rel_path);
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&full_path, &blob.data)?;

                let metadata = fs::metadata(&full_path)?;
                new_index.entries.push(IndexEntry {
                    path: rel_path.clone(),
                                       hash: hash.clone(),
                                       mode: FileMode::Regular,
                                       modified_at: metadata.modified()?,
                                       file_size: metadata.len(),
                });
            }
        }

        let current_head_hash = self.get_head_commit_hash().unwrap_or_default();
        if let Ok(current_files) = self.flatten_tree_from_commit(&current_head_hash) {
            for (rel_path, _) in current_files {
                if !target_files.contains_key(&rel_path) {
                    let full_path = self.worktree.join(&rel_path);
                    if full_path.exists() {
                        let _ = fs::remove_file(full_path);
                    }
                }
            }
        }

        new_index.save(&self.brass_dir.join("index"))?;

        if target_ref_path.exists() {
            let rel_suffix = target_ref_path.strip_prefix(&self.brass_dir).unwrap_or(&target_ref_path);
            fs::write(self.brass_dir.join("HEAD"), format!("ref: {}\n", rel_suffix.display()))?;
        } else {
            fs::write(self.brass_dir.join("HEAD"), format!("{}\n", commit_hash))?;
        }

        Ok(())
    }

    pub fn diff(&self, target_path: Option<PathBuf>, index: &Index) -> std::io::Result<()> {
        let index_map: HashMap<PathBuf, String> = index.entries.iter().map(|e| (e.path.clone(), e.hash.clone())).collect();

        if let Some(path) = target_path {
            self.diff_single_file(&path, index_map.get(&path))?;
        } else {
            for entry in &index.entries {
                self.diff_single_file(&entry.path, Some(&entry.hash))?;
            }
        }
        Ok(())
    }

    fn diff_single_file(&self, path: &Path, index_hash: Option<&String>) -> std::io::Result<()> {
        let full_path = self.worktree.join(path);
        if !full_path.exists() {
            println!("Deleted: {}", path.display());
            return Ok(());
        }

        let disk_text = fs::read_to_string(&full_path)?;
        let index_text = if let Some(hash) = index_hash {
            if let Ok(BrassObject::Blob(blob)) = self.read_object(hash) {
                String::from_utf8_lossy(&blob.data).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let ops = self.compute_diff(&index_text, &disk_text);
        let mut has_changes = false;

        for op in &ops {
            if !matches!(op, DiffOp::Keep(_)) {
                has_changes = true;
                break;
            }
        }

        if has_changes {
            println!("--- a/{}", path.display());
            println!("+++ b/{}", path.display());
            for op in ops {
                match op {
                    DiffOp::Keep(line) => println!(" {}", line),
                    DiffOp::Insert(line) => println!("+{}", line),
                    DiffOp::Delete(line) => println!("-{}", line),
                }
            }
        }

        Ok(())
    }

    fn compute_diff(&self, old_text: &str, new_text: &str) -> Vec<DiffOp> {
        let old_lines: Vec<&str> = old_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        let n = old_lines.len();
        let m = new_lines.len();
        let mut lcs = vec![vec![0; m + 1]; n + 1];

        for i in 0..n {
            for j in 0..m {
                if old_lines[i] == new_lines[j] {
                    lcs[i + 1][j + 1] = lcs[i][j] + 1;
                } else {
                    lcs[i + 1][j + 1] = usize::max(lcs[i + 1][j], lcs[i][j + 1]);
                }
            }
        }

        let mut i = n;
        let mut j = m;
        let mut ops = Vec::new();

        while i > 0 || j > 0 {
            if i > 0 && j > 0 && old_lines[i - 1] == new_lines[j - 1] {
                ops.push(DiffOp::Keep(old_lines[i - 1].to_string()));
                i -= 1;
                j -= 1;
            } else if j > 0 && (i == 0 || lcs[i][j - 1] >= lcs[i - 1][j]) {
                ops.push(DiffOp::Insert(new_lines[j - 1].to_string()));
                j -= 1;
            } else if i > 0 && (j == 0 || lcs[i][j - 1] < lcs[i - 1][j]) {
                ops.push(DiffOp::Delete(old_lines[i - 1].to_string()));
                i -= 1;
            }
        }

        ops.reverse();
        ops
    }

    pub fn merge_leaf(&self, leaf_name: &str) -> std::io::Result<LeafMergeResult> {
        let target_commit_hash = self.get_head_commit_hash()?;
        let leaf_ref = RefKind::Leaf {
            user: self.config.user_name.clone(),
            name: leaf_name.to_string(),
        };

        let leaf_ref_path = self.brass_dir.join(leaf_ref.to_path_suffix());
        if !leaf_ref_path.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Liść nie istnieje"));
        }

        let leaf_commit_hash = fs::read_to_string(leaf_ref_path)?.trim().to_string();
        let lca_hash = match self.find_lca(&target_commit_hash, &leaf_commit_hash)? {
            Some(hash) => hash,
            None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Brak wspólnego przodka")),
        };

        let base_map = self.flatten_tree_from_commit(&lca_hash)?;
        let target_map = self.flatten_tree_from_commit(&target_commit_hash)?;
        let leaf_map = self.flatten_tree_from_commit(&leaf_commit_hash)?;

        let mut all_paths = HashSet::new();
        all_paths.extend(base_map.keys().cloned());
        all_paths.extend(target_map.keys().cloned());
        all_paths.extend(leaf_map.keys().cloned());

        let mut merged_entries = Vec::new();
        let mut has_conflicts = false;

        for path in all_paths {
            let base_h = base_map.get(&path).cloned();
            let target_h = target_map.get(&path).cloned();
            let leaf_h = leaf_map.get(&path).cloned();

            if leaf_h != base_h && !self.acl.can_write(&self.config.user_name, &path) {
                return Ok(LeafMergeResult::PermissionDenied {
                    user: self.config.user_name.clone(),
                          forbidden_path: path,
                });
            }

            if target_h == leaf_h {
                if let Some(h) = target_h {
                    merged_entries.push(TreeEntry { mode: FileMode::Regular, name: path.to_string_lossy().to_string(), hash: h });
                }
            } else if base_h == target_h {
                if let Some(h) = leaf_h {
                    merged_entries.push(TreeEntry { mode: FileMode::Regular, name: path.to_string_lossy().to_string(), hash: h });
                }
            } else if base_h == leaf_h {
                if let Some(h) = target_h {
                    merged_entries.push(TreeEntry { mode: FileMode::Regular, name: path.to_string_lossy().to_string(), hash: h });
                }
            } else {
                let base_text = self.read_blob_as_string(base_h.as_deref());
                let target_text = self.read_blob_as_string(target_h.as_deref());
                let leaf_text = self.read_blob_as_string(leaf_h.as_deref());

                let chunks = self.three_way_line_merge(&base_text, &target_text, &leaf_text);
                let (has_conflict, content) = self.format_merged_chunks(&chunks, leaf_name);

                let full_path = self.worktree.join(&path);
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&full_path, &content)?;

                if has_conflict {
                    has_conflicts = true;
                } else {
                    let blob_hash = self.write_object(&BrassObject::Blob(Blob { data: content.into_bytes() }))?;
                    merged_entries.push(TreeEntry { mode: FileMode::Regular, name: path.to_string_lossy().to_string(), hash: blob_hash });
                }
            }
        }

        if has_conflicts {
            return Ok(LeafMergeResult::ConflictInLeaf { path: PathBuf::from("Pliki z konfliktami zapisano na dysku") });
        }

        let merged_tree = BrassObject::Tree(Tree { entries: merged_entries });
        let tree_hash = self.write_object(&merged_tree)?;

        let merge_commit = BrassObject::Commit(Commit {
            tree_hash,
            parent_hashes: vec![target_commit_hash, leaf_commit_hash],
            author: Signature {
                name: self.config.user_name.clone(),
                                               email: self.config.user_email.clone(),
                                               timestamp: SystemTime::now(),
            },
            committer: Signature {
                name: self.config.user_name.clone(),
                                               email: self.config.user_email.clone(),
                                               timestamp: SystemTime::now(),
            },
            message: format!("Merge leaf '{}' into target", leaf_name),
        });

        let new_commit_hash = self.write_object(&merge_commit)?;
        self.update_head_target(&new_commit_hash)?;

        Ok(LeafMergeResult::Success(new_commit_hash))
    }

    fn read_blob_as_string(&self, hash: Option<&str>) -> String {
        match hash {
            Some(h) => {
                if let Ok(BrassObject::Blob(blob)) = self.read_object(h) {
                    String::from_utf8_lossy(&blob.data).to_string()
                } else {
                    String::new()
                }
            }
            None => String::new(),
        }
    }

    fn three_way_line_merge(&self, base: &str, target: &str, leaf: &str) -> Vec<MergeChunk> {
        let base_lines: Vec<&str> = base.lines().collect();
        let target_lines: Vec<&str> = target.lines().collect();
        let leaf_lines: Vec<&str> = leaf.lines().collect();

        if target == base {
            return vec![MergeChunk::Clean(leaf_lines.iter().map(|s| s.to_string()).collect())];
        }
        if leaf == base || target == leaf {
            return vec![MergeChunk::Clean(target_lines.iter().map(|s| s.to_string()).collect())];
        }

        let diff_target = self.compute_diff(base, target);
        let diff_leaf = self.compute_diff(base, leaf);

        if diff_target == diff_leaf {
            return vec![MergeChunk::Clean(target_lines.iter().map(|s| s.to_string()).collect())];
        }

        let mut chunks = Vec::new();
        let mut t_idx = 0;
        let mut l_idx = 0;

        while t_idx < target_lines.len() || l_idx < leaf_lines.len() {
            if t_idx < target_lines.len() && l_idx < leaf_lines.len() && target_lines[t_idx] == leaf_lines[l_idx] {
                chunks.push(MergeChunk::Clean(vec![target_lines[t_idx].to_string()]));
                t_idx += 1;
                l_idx += 1;
            } else {
                let mut t_conflict = Vec::new();
                let mut l_conflict = Vec::new();

                while t_idx < target_lines.len() && (l_idx >= leaf_lines.len() || target_lines[t_idx] != leaf_lines[l_idx]) {
                    t_conflict.push(target_lines[t_idx].to_string());
                    t_idx += 1;
                }

                while l_idx < leaf_lines.len() && (t_idx >= target_lines.len() || target_lines[t_idx] != leaf_lines[l_idx]) {
                    l_conflict.push(leaf_lines[l_idx].to_string());
                    l_idx += 1;
                }

                chunks.push(MergeChunk::Conflict {
                    target: t_conflict,
                    leaf: l_conflict,
                });
            }
        }

        chunks
    }

    fn format_merged_chunks(&self, chunks: &[MergeChunk], leaf_name: &str) -> (bool, String) {
        let mut out = String::new();
        let mut has_conflict = false;

        for chunk in chunks {
            match chunk {
                MergeChunk::Clean(lines) => {
                    for line in lines {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
                MergeChunk::Conflict { target, leaf } => {
                    has_conflict = true;
                    out.push_str("<<<<<<< TARGET\n");
                    for line in target {
                        out.push_str(line);
                        out.push('\n');
                    }
                    out.push_str("=======\n");
                    for line in leaf {
                        out.push_str(line);
                        out.push('\n');
                    }
                    out.push_str(&format!(">>>>>>> LEAF ({})\n", leaf_name));
                }
            }
        }

        (has_conflict, out)
    }

    pub fn log(&self, limit: Option<usize>) -> std::io::Result<()> {
        let mut current_hash = match self.get_head_commit_hash() {
            Ok(h) => h,
            Err(_) => {
                println!("Brak commitów w historii.");
                return Ok(());
            }
        };

        let mut count = 0;
        let mut visited = HashSet::new();

        while !current_hash.is_empty() {
            if let Some(max) = limit {
                if count >= max {
                    break;
                }
            }

            if !visited.insert(current_hash.clone()) {
                break;
            }

            match self.read_object(&current_hash) {
                Ok(BrassObject::Commit(commit)) => {
                    println!("\x1b[33mcommit {}\x1b[0m", current_hash);
                    if !commit.parent_hashes.is_empty() {
                        println!("Parents: {}", commit.parent_hashes.join(" "));
                    }
                    println!("Author: {} <{}>", commit.author.name, commit.author.email);
                    println!("\n    {}\n", commit.message);

                    count += 1;
                    if let Some(parent) = commit.parent_hashes.first() {
                        current_hash = parent.clone();
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        Ok(())
    }

    pub fn blame(&self, target_path: &Path) -> std::io::Result<()> {
        let head_hash = self.get_head_commit_hash()?;
        let disk_text = fs::read_to_string(self.worktree.join(target_path))?;
        let lines: Vec<&str> = disk_text.lines().collect();

        let mut line_authors: Vec<Option<(String, String)>> = vec![None; lines.len()];
        let mut current_commit_hash = head_hash;

        while !current_commit_hash.is_empty() {
            if let Ok(BrassObject::Commit(commit)) = self.read_object(&current_commit_hash) {
                let commit_files = self.flatten_tree_from_commit(&current_commit_hash)?;
                if let Some(blob_hash) = commit_files.get(target_path) {
                    let commit_text = self.read_blob_as_string(Some(blob_hash));
                    let commit_lines: Vec<&str> = commit_text.lines().collect();

                    for (idx, line) in lines.iter().enumerate() {
                        if line_authors[idx].is_none() && commit_lines.contains(line) {
                            let short_hash = &current_commit_hash[..7];
                            let author_info = format!("{} ({})", short_hash, commit.author.name);
                            line_authors[idx] = Some((author_info, line.to_string()));
                        }
                    }
                }

                if let Some(parent) = commit.parent_hashes.first() {
                    current_commit_hash = parent.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        println!("--- Blame dla {:?} ---", target_path);
        for (idx, item) in line_authors.iter().enumerate() {
            if let Some((info, line_content)) = item {
                println!("{:4} | {:<25} | {}", idx + 1, info, line_content);
            } else {
                println!("{:4} | {:<25} | {}", idx + 1, "Uncommitted change", lines[idx]);
            }
        }

        Ok(())
    }

    pub fn create_tag(&self, name: &str, target_hash: Option<&str>) -> std::io::Result<PathBuf> {
        let commit_hash = match target_hash {
            Some(h) => h.to_string(),
            None => self.get_head_commit_hash()?,
        };

        let tag_path = self.brass_dir.join("refs").join("tags").join(name);
        if let Some(parent) = tag_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&tag_path, format!("{}\n", commit_hash))?;
        Ok(tag_path)
    }

    pub fn list_tags(&self) -> std::io::Result<Vec<(String, String)>> {
        let tags_dir = self.brass_dir.join("refs").join("tags");
        let mut result = Vec::new();

        if !tags_dir.exists() {
            return Ok(result);
        }

        for entry in fs::read_dir(tags_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                let hash = fs::read_to_string(entry.path())?.trim().to_string();
                result.push((name, hash));
            }
        }
        Ok(result)
    }

    pub fn delete_tag(&self, name: &str) -> std::io::Result<()> {
        let tag_path = self.brass_dir.join("refs").join("tags").join(name);
        if tag_path.exists() {
            fs::remove_file(tag_path)?;
            Ok(())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Tag nie istnieje"))
        }
    }

    pub fn gc(&self) -> std::io::Result<usize> {
        let reachable = self.collect_all_reachable_hashes()?;
        let objects_dir = self.brass_dir.join("objects");
        let mut removed_count = 0;

        if !objects_dir.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(&objects_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let prefix = entry.file_name().to_string_lossy().to_string();
                for obj_entry in fs::read_dir(entry.path())? {
                    let obj_entry = obj_entry?;
                    let suffix = obj_entry.file_name().to_string_lossy().to_string();
                    let full_hash = format!("{}{}", prefix, suffix);

                    if !reachable.contains(&full_hash) {
                        fs::remove_file(obj_entry.path())?;
                        removed_count += 1;
                    }
                }

                if fs::read_dir(entry.path())?.next().is_none() {
                    let _ = fs::remove_dir(entry.path());
                }
            }
        }

        Ok(removed_count)
    }

    pub fn pack(&self) -> std::io::Result<(usize, PathBuf)> {
        let objects_dir = self.brass_dir.join("objects");
        if !objects_dir.exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Katalog obiektów nie istnieje"));
        }

        let mut loose_objects = Vec::new();
        for entry in fs::read_dir(&objects_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let prefix = entry.file_name().to_string_lossy().to_string();
                for obj_entry in fs::read_dir(entry.path())? {
                    let obj_entry = obj_entry?;
                    let suffix = obj_entry.file_name().to_string_lossy().to_string();
                    let full_hash = format!("{}{}", prefix, suffix);
                    loose_objects.push((full_hash, obj_entry.path()));
                }
            }
        }

        if loose_objects.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Brak obiektów do spakowania"));
        }

        let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
        let pack_name = format!("pack-{}", timestamp);
        let pack_path = self.brass_dir.join("packs").join(format!("{}.pack", pack_name));
        let idx_path = self.brass_dir.join("packs").join(format!("{}.idx", pack_name));

        fs::create_dir_all(self.brass_dir.join("packs"))?;

        let mut pack_file = File::create(&pack_path)?;
        let mut idx_file = File::create(&idx_path)?;

        let mut current_offset: u64 = 0;
        let mut packed_count = 0;

        for (hash, path) in &loose_objects {
            let compressed_data = fs::read(path)?;
            let len = compressed_data.len();

            pack_file.write_all(&compressed_data)?;
            writeln!(idx_file, "{}\t{}\t{}", hash, current_offset, len)?;

            current_offset += len as u64;
            packed_count += 1;
        }

        for (_, path) in loose_objects {
            let _ = fs::remove_file(&path);
        }

        Ok((packed_count, pack_path))
    }

    fn collect_all_reachable_hashes(&self) -> std::io::Result<HashSet<String>> {
        let mut reachable = HashSet::new();
        let mut root_hashes = Vec::new();

        if let Ok(head_hash) = self.get_head_commit_hash() {
            root_hashes.push(head_hash);
        }

        let refs_dir = self.brass_dir.join("refs");
        if refs_dir.exists() {
            self.collect_refs_from_dir(&refs_dir, &mut root_hashes)?;
        }

        let index_path = self.brass_dir.join("index");
        if let Ok(index) = Index::load(&index_path) {
            for entry in index.entries {
                reachable.insert(entry.hash);
            }
        }

        let mut queue = VecDeque::from(root_hashes);
        while let Some(hash) = queue.pop_front() {
            if reachable.insert(hash.clone()) {
                if let Ok(obj) = self.read_object(&hash) {
                    match obj {
                        BrassObject::Commit(commit) => {
                            queue.push_back(commit.tree_hash);
                            for p in commit.parent_hashes {
                                queue.push_back(p);
                            }
                        }
                        BrassObject::Tree(tree) => {
                            for entry in tree.entries {
                                queue.push_back(entry.hash);
                            }
                        }
                        BrassObject::Blob(_) => {}
                    }
                }
            }
        }

        Ok(reachable)
    }

    fn collect_refs_from_dir(&self, root_dir: &Path, root_hashes: &mut Vec<String>) -> std::io::Result<()> {
        let mut queue = VecDeque::new();
        queue.push_back(root_dir.to_path_buf());

        while let Some(current_dir) = queue.pop_front() {
            for entry in fs::read_dir(current_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    queue.push_back(path);
                } else if path.is_file() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let hash = content.trim().to_string();
                        if !hash.is_empty() && !hash.starts_with("ref: ") {
                            root_hashes.push(hash);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn create_leaf(&self, leaf_name: &str) -> std::io::Result<PathBuf> {
        let current_head = self.get_head_commit_hash()?;
        let leaf_ref = RefKind::Leaf {
            user: self.config.user_name.clone(),
            name: leaf_name.to_string(),
        };

        let ref_path = self.brass_dir.join(leaf_ref.to_path_suffix());
        if let Some(parent) = ref_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&ref_path, format!("{}\n", current_head))?;
        fs::write(self.brass_dir.join("HEAD"), format!("ref: {}\n", leaf_ref.to_path_suffix().to_string_lossy()))?;

        Ok(ref_path)
    }

    pub fn list_leaves(&self) -> std::io::Result<Vec<String>> {
        let leaves_dir = self.brass_dir.join("refs").join("leaves");
        let mut result = Vec::new();

        if !leaves_dir.exists() {
            return Ok(result);
        }

        let mut queue = VecDeque::new();
        queue.push_back(leaves_dir);

        while let Some(current_dir) = queue.pop_front() {
            for entry in fs::read_dir(current_dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;

                if ft.is_dir() {
                    queue.push_back(entry.path());
                } else if ft.is_file() {
                    if let Ok(rel_path) = entry.path().strip_prefix(self.brass_dir.join("refs").join("leaves")) {
                        result.push(rel_path.to_string_lossy().to_string());
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn status(&self, index: &Index) -> std::io::Result<()> {
        let mut head_files = HashMap::new();
        if let Ok(head_hash) = self.get_head_commit_hash() {
            head_files = self.flatten_tree_from_commit(&head_hash)?;
        }

        let mut staged_entries = Vec::new();
        let mut unstaged_entries = Vec::new();
        let mut index_map = HashMap::new();

        for entry in &index.entries {
            index_map.insert(entry.path.clone(), entry.hash.clone());
            let head_h = head_files.get(&entry.path);
            if head_h != Some(&entry.hash) {
                staged_entries.push((entry.path.clone(), "staged"));
            }
        }

        let mut untracked = Vec::new();
        self.scan_worktree(&self.worktree, index, &mut unstaged_entries, &mut untracked)?;

        for (head_path, _) in head_files {
            if !index_map.contains_key(&head_path) {
                staged_entries.push((head_path, "deleted (staged)"));
            }
        }

        println!("--- Staged Changes ---");
        for (path, status) in staged_entries {
            println!("  {}: {}", status, path.display());
        }

        println!("\n--- Unstaged Changes ---");
        for (path, status) in unstaged_entries {
            println!("  {}: {}", status, path.display());
        }

        println!("\n--- Untracked Files ---");
        for path in untracked {
            println!("  {}", path.display());
        }

        Ok(())
    }

    fn scan_worktree(
        &self,
        base_dir: &Path,
        index: &Index,
        unstaged: &mut Vec<(PathBuf, &'static str)>,
                     untracked: &mut Vec<PathBuf>,
    ) -> std::io::Result<()> {
        let mut queue = VecDeque::new();
        queue.push_back(PathBuf::new());

        while let Some(rel_dir) = queue.pop_front() {
            let current_dir = base_dir.join(&rel_dir);
            for entry in fs::read_dir(current_dir)? {
                let entry = entry?;
                let file_name = entry.file_name();
                let rel_path = rel_dir.join(file_name);

                if self.ignore.is_ignored(&rel_path) {
                    continue;
                }

                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    queue.push_back(rel_path);
                } else if file_type.is_file() {
                    if let Some(idx_entry) = index.entries.iter().find(|e| e.path == rel_path) {
                        let disk_data = fs::read(base_dir.join(&rel_path))?;
                        let (disk_hash, _) = BrassObject::Blob(Blob { data: disk_data }).serialize();
                        if disk_hash != idx_entry.hash {
                            unstaged.push((rel_path, "modified"));
                        }
                    } else {
                        untracked.push(rel_path);
                    }
                }
            }
        }
        Ok(())
    }

    fn flatten_tree_from_commit(&self, commit_hash: &str) -> std::io::Result<HashMap<PathBuf, String>> {
        let mut result = HashMap::new();
        if let Ok(BrassObject::Commit(commit)) = self.read_object(commit_hash) {
            self.collect_tree_entries(&commit.tree_hash, &mut result)?;
        }
        Ok(result)
    }

    fn collect_tree_entries(&self, initial_tree_hash: &str, map: &mut HashMap<PathBuf, String>) -> std::io::Result<()> {
        let mut queue = VecDeque::new();
        queue.push_back((initial_tree_hash.to_string(), PathBuf::new()));

        while let Some((tree_hash, prefix)) = queue.pop_front() {
            if let Ok(BrassObject::Tree(tree)) = self.read_object(&tree_hash) {
                for entry in tree.entries {
                    let path = prefix.join(&entry.name);
                    if entry.mode == FileMode::Directory {
                        queue.push_back((entry.hash, path));
                    } else {
                        map.insert(path, entry.hash);
                    }
                }
            }
        }
        Ok(())
    }

    fn find_lca(&self, commit_a: &str, commit_b: &str) -> std::io::Result<Option<String>> {
        let mut ancestors_a = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(commit_a.to_string());

        while let Some(hash) = queue.pop_front() {
            if ancestors_a.insert(hash.clone()) {
                if let Ok(BrassObject::Commit(c)) = self.read_object(&hash) {
                    for p in c.parent_hashes {
                        queue.push_back(p);
                    }
                }
            }
        }

        queue.push_back(commit_b.to_string());
        let mut visited_b = HashSet::new();

        while let Some(hash) = queue.pop_front() {
            if ancestors_a.contains(&hash) {
                return Ok(Some(hash));
            }
            if visited_b.insert(hash.clone()) {
                if let Ok(BrassObject::Commit(c)) = self.read_object(&hash) {
                    for p in c.parent_hashes {
                        queue.push_back(p);
                    }
                }
            }
        }

        Ok(None)
    }

    fn get_head_commit_hash(&self) -> std::io::Result<String> {
        let head_content = fs::read_to_string(self.brass_dir.join("HEAD"))?;
        let head_content = head_content.trim();

        if let Some(ref_path) = head_content.strip_prefix("ref: ") {
            let full_ref_path = self.brass_dir.join(ref_path);
            let commit_hash = fs::read_to_string(full_ref_path)?;
            Ok(commit_hash.trim().to_string())
        } else {
            Ok(head_content.to_string())
        }
    }

    fn update_head_target(&self, commit_hash: &str) -> std::io::Result<()> {
        let head_content = fs::read_to_string(self.brass_dir.join("HEAD"))?;
        let head_content = head_content.trim();

        if let Some(ref_path) = head_content.strip_prefix("ref: ") {
            let full_ref_path = self.brass_dir.join(ref_path);
            if let Some(parent) = full_ref_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(full_ref_path, format!("{}\n", commit_hash))?;
        } else {
            fs::write(self.brass_dir.join("HEAD"), format!("{}\n", commit_hash))?;
        }
        Ok(())
    }
}

impl BrassObject {
    pub fn serialize(&self) -> (String, Vec<u8>) {
        let (kind_str, payload) = match self {
            BrassObject::Blob(b) => ("blob", b.data.clone()),
            BrassObject::Tree(t) => ("tree", t.serialize_payload()),
            BrassObject::Commit(c) => ("commit", c.serialize_payload().into_bytes()),
        };

        let header = format!("{} {}\0", kind_str, payload.len());
        let mut ful_data = header.into_bytes();
        ful_data.extend_from_slice(&payload);

        let mut hasher = Sha256::new();
        hasher.update(&ful_data);
        (format!("{:x}", hasher.finalize()), ful_data)
    }
}

impl Tree {
    pub fn serialize_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            let line = format!("{:?} {}\0{}\n", entry.mode, entry.name, entry.hash);
            buf.extend_from_slice(line.as_bytes());
        }
        buf
    }

    pub fn deserialize_payload(payload: &[u8]) -> std::io::Result<Self> {
        let mut entries = Vec::new();
        let reader = BufReader::new(payload);

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('\0').collect();
            if parts.len() == 2 {
                let header_parts: Vec<&str> = parts[0].split_whitespace().collect();
                let mode = match header_parts.first().copied() {
                    Some("Regular") => FileMode::Regular,
                    Some("Executable") => FileMode::Executable,
                    _ => FileMode::Directory,
                };
                let name = header_parts.get(1).unwrap_or(&"").to_string();
                let hash = parts[1].trim().to_string();
                entries.push(TreeEntry { mode, name, hash });
            }
        }
        Ok(Self { entries })
    }
}

impl Commit {
    pub fn serialize_payload(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("tree {}\n", self.tree_hash));
        for parent in &self.parent_hashes {
            out.push_str(&format!("parent {}\n", parent));
        }
        out.push_str(&format!("author {} <{}>\n", self.author.name, self.author.email));
        out.push_str(&format!("committer {} <{}>\n", self.committer.name, self.committer.email));
        out.push_str(&format!("\n{}\n", self.message));
        out
    }

    pub fn deserialize_payload(payload: &[u8]) -> std::io::Result<Self> {
        let content = String::from_utf8_lossy(payload);
        let mut tree_hash = String::new();
        let mut parent_hashes = Vec::new();
        let mut author = Signature {
            name: String::new(),
            email: String::new(),
            timestamp: SystemTime::now(),
        };
        let mut committer = author.clone();
        let mut message = String::new();
        let mut in_message = false;

        for line in content.lines() {
            if in_message {
                message.push_str(line);
                message.push('\n');
                continue;
            }

            if line.is_empty() {
                in_message = true;
                continue;
            }

            if let Some(hash) = line.strip_prefix("tree ") {
                tree_hash = hash.to_string();
            } else if let Some(hash) = line.strip_prefix("parent ") {
                parent_hashes.push(hash.to_string());
            } else if let Some(auth) = line.strip_prefix("author ") {
                if let Some((name, email)) = auth.split_once(" <") {
                    author.name = name.to_string();
                    author.email = email.trim_end_matches('>').to_string();
                }
            } else if let Some(comm) = line.strip_prefix("committer ") {
                if let Some((name, email)) = comm.split_once(" <") {
                    committer.name = name.to_string();
                    committer.email = comm.trim_end_matches('>').to_string();
                }
            }
        }

        Ok(Self {
            tree_hash,
            parent_hashes,
            author,
            committer,
            message: message.trim().to_string(),
        })
    }
}

impl Index {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 3 {
                let mode = match parts[0] {
                    "100755" => FileMode::Executable,
                    "040000" => FileMode::Directory,
                    _ => FileMode::Regular,
                };
                let hash = parts[1].to_string();
                let relative_path = PathBuf::from(parts[2]);

                entries.push(IndexEntry {
                    path: relative_path,
                    hash,
                    mode,
                    modified_at: SystemTime::now(),
                             file_size: 0,
                });
            }
        }
        Ok(Self { entries })
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        for entry in &self.entries {
            let mode_str = match entry.mode {
                FileMode::Executable => "100755",
                FileMode::Directory => "040000",
                FileMode::Regular => "100644",
            };
            writeln!(file, "{}\t{}\t{}", mode_str, entry.hash, entry.path.to_string_lossy())?;
        }
        Ok(())
    }
}

impl BrassConfig {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let xml_str = to_string(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, xml_str)
    }
}

#[async_trait::async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub async fn network_push_pack(
    server_addr: &str,
    pack_data: &[u8],
    remote_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(Config::default());
    let addrs: Vec<_> = tokio::net::lookup_host(server_addr).await?.collect();
    let mut handle = russh::client::connect(config, &addrs[..], ClientHandler).await?;

    let _ = handle.authenticate_password("brass_user", "").await?;

    let mut channel = handle.channel_open_session().await?;
    let cmd = format!("brass-receive-pack {}", remote_ref);
    channel.exec(true, cmd.as_bytes()).await?;

    channel.data(&pack_data[..]).await?;
    channel.eof().await?;

    while let Some(msg) = channel.wait().await {
        if let russh::ChannelMsg::Data { data } = msg {
            print!("[REMOTE] {}", String::from_utf8_lossy(&data));
        }
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let current_dir = std::env::current_dir().unwrap();

    match cli.command {
        Commands::Init => match Repository::init(&current_dir) {
            Ok(_) => println!("Inicjalizacja repozytorium Brass w {:?}", current_dir.join(".brass_control")),
            Err(e) => eprintln!("Błąd inicjalizacji: {}", e),
        },
        Commands::Add { path } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            let index_path = repo.brass_dir.join("index");
            let mut index = Index::load(&index_path).unwrap_or_default();

            if let Err(e) = repo.add(&path, &mut index) {
                eprintln!("Błąd podczas dodawania pliku: {}", e);
            } else if let Err(e) = index.save(&index_path) {
                eprintln!("Błąd zapisu indeksu: {}", e);
            } else {
                println!("Dodano {:?} do indeksu", path);
            }
        }
        Commands::Commit { message } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            let index_path = repo.brass_dir.join("index");
            let index = Index::load(&index_path).unwrap_or_default();

            let author = Signature {
                name: repo.config.user_name.clone(),
                email: repo.config.user_email.clone(),
                timestamp: SystemTime::now(),
            };

            match repo.commit(message, author, &index) {
                Ok(hash) => println!("Utworzono commit: {}", hash),
                Err(e) => eprintln!("Błąd tworzenia commita: {}", e),
            }
        }
        Commands::Status => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            let index_path = repo.brass_dir.join("index");
            let index = Index::load(&index_path).unwrap_or_default();
            if let Err(e) = repo.status(&index) {
                eprintln!("Błąd statusu: {}", e);
            }
        }
        Commands::Checkout { target } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match repo.checkout(&target) {
                Ok(_) => println!("Przełączono stan roboczy na: {}", target),
                Err(e) => eprintln!("Błąd checkout: {}", e),
            }
        }
        Commands::Diff { path } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            let index_path = repo.brass_dir.join("index");
            let index = Index::load(&index_path).unwrap_or_default();

            if let Err(e) = repo.diff(path, &index) {
                eprintln!("Błąd wyliczania diff: {}", e);
            }
        }
        Commands::CatObject { hash } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match repo.read_object(&hash) {
                Ok(BrassObject::Blob(b)) => println!("{}", String::from_utf8_lossy(&b.data)),
                Ok(BrassObject::Tree(t)) => {
                    for entry in t.entries {
                        println!("{:?} {}\t{}", entry.mode, entry.hash, entry.name);
                    }
                }
                Ok(BrassObject::Commit(c)) => {
                    println!("Tree: {}", c.tree_hash);
                    println!("Author: {} <{}>", c.author.name, c.author.email);
                    println!("\n{}", c.message);
                }
                Err(e) => eprintln!("Nie udało się odczytać obiektu: {}", e),
            }
        }
        Commands::Tag { command } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match command {
                TagCommands::Create { name, target } => match repo.create_tag(&name, target.as_deref()) {
                    Ok(path) => println!("Utworzono Tag '{}' pod {:?}", name, path),
                    Err(e) => eprintln!("Błąd tworzenia taga: {}", e),
                },
                TagCommands::List => match repo.list_tags() {
                    Ok(tags) => {
                        println!("--- Tagi / Release ---");
                        for (tag, hash) in tags {
                            println!("  {} -> {}", tag, hash);
                        }
                    }
                    Err(e) => eprintln!("Błąd listowania tagów: {}", e),
                },
                TagCommands::Delete { name } => match repo.delete_tag(&name) {
                    Ok(_) => println!("Usunięto Tag '{}'", name),
                    Err(e) => eprintln!("Błąd usuwania taga: {}", e),
                },
            }
        }
        Commands::Gc => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match repo.gc() {
                Ok(count) => println!("Garbage Collection: usunięto {} osieroconych obiektów z dysku", count),
                Err(e) => eprintln!("Błąd podczas wykonywania GC: {}", e),
            }
        }
        Commands::Pack => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match repo.pack() {
                Ok((count, path)) => println!("Spakowano {} luźnych obiektów do paczki {:?}", count, path),
                Err(e) => eprintln!("Błąd pakowania obiektów: {}", e),
            }
        }
        Commands::Leaf { command } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match command {
                LeafCommands::Create { name } => match repo.create_leaf(&name) {
                    Ok(path) => println!("Utworzono i przełączono na Liść: {:?}", path),
                    Err(e) => eprintln!("Błąd tworzenia Liścia: {}", e),
                },
                LeafCommands::List => match repo.list_leaves() {
                    Ok(leaves) => {
                        println!("--- Dostępne Liście ---");
                        for leaf in leaves {
                            println!("  {}", leaf);
                        }
                    }
                    Err(e) => eprintln!("Błąd listowania Liści: {}", e),
                },
                LeafCommands::Merge { name } => match repo.merge_leaf(&name) {
                    Ok(LeafMergeResult::Success(hash)) => println!("Pomyślnie scalono Liść '{}', commit: {}", name, hash),
                    Ok(LeafMergeResult::PermissionDenied { user, forbidden_path }) => {
                        eprintln!("Brak uprawnień ACL dla użytkownika '{}' na ścieżce {:?}", user, forbidden_path);
                    }
                    Ok(LeafMergeResult::ConflictInLeaf { .. }) => {
                        eprintln!("Wystąpiły konflikty podczas scalania. Markery konfliktów zapisano w plikach roboczych.");
                    }
                    Err(e) => eprintln!("Błąd podczas scalania Liścia: {}", e),
                },
            }
        }
        Commands::Log { limit } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            if let Err(e) = repo.log(limit) {
                eprintln!("Błąd wyświetlania logu: {}", e);
            }
        }
        Commands::Blame { path } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            if let Err(e) = repo.blame(&path) {
                eprintln!("Błąd podczas blame: {}", e);
            }
        }
        Commands::Push { remote, ref_name } => {
            let repo = Repository::init(&current_dir).expect("Nie znaleziono repozytorium");
            match repo.pack() {
                Ok((_count, pack_path)) => {
                    let pack_bytes = fs::read(&pack_path).expect("Błąd odczytu spakowanego pliku");
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        println!("Wysyłanie paczki na serwer {}...", remote);
                        if let Err(e) = network_push_pack(&remote, &pack_bytes, &ref_name).await {
                            eprintln!("Błąd podczas pushowania: {}", e);
                        } else {
                            println!("Pomyślnie wysłano dane na serwer.");
                        }
                    });
                }
                Err(e) => eprintln!("Nie udało się spakować obiektów przed wysłaniem: {}", e),
            }
        }
    }
}
