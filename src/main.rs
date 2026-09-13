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
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// enum
#[derive(Parser, Debug)]
#[command(name = "brass", author, version, about = "Brass Control")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// enum
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
    CatObject {
        #[arg(required = true)]
        hash: String,
    },
    Leaf {
        #[command(subcommand)]
        command: LeafCommands,
    },
}

// enum
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

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub data: Vec<u8>,
}

// enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMode {
    Regular,
    Executable,
    Directory,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: FileMode,
    pub name: String,
    pub hash: String,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub email: String,
    pub timestamp: SystemTime,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree_hash: String,
    pub parent_hashes: Vec<String>,
    pub author: Signature,
    pub committer: Signature,
    pub message: String,
}

// enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrassObject {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
}

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: PathBuf,
    pub hash: String,
    pub mode: FileMode,
    pub modified_at: SystemTime,
    pub file_size: u64,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Index {
    pub entries: Vec<IndexEntry>,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "brass_config")]
pub struct BrassConfig {
    pub user_name: String,
    pub user_email: String,
    pub default_branch: String,
    pub is_admin: bool,
}

// impl
impl Default for BrassConfig {
    // fn
    fn default() -> Self {
        Self {
            user_name: String::from("Anonymous"),
            user_email: String::from("user@localhost"),
            default_branch: String::from("main"),
                is_admin: false,
        }
    }
}

// enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessLevel {
    ReadOnly,
    ReadWrite,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRule {
    pub user: String,
    pub path_pattern: String,
    pub access: AccessLevel,
}

// struct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename = "brass_acl")]
pub struct AclConfig {
    pub rules: Vec<AccessRule>,
}

// impl
impl AclConfig {
    // fn
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    // fn
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let xml_str = to_string(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, xml_str)
    }

    // fn
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

// enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    Branch(String),
    Leaf { user: String, name: String },
}

// impl
impl RefKind {
    // fn
    pub fn to_path_suffix(&self) -> PathBuf {
        match self {
            RefKind::Branch(name) => PathBuf::from("refs").join("heads").join(name),
            RefKind::Leaf { user, name } => PathBuf::from("refs").join("leaves").join(user).join(name),
        }
    }
}

// enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafMergeResult {
    Success(String),
    PermissionDenied { user: String, forbidden_path: PathBuf },
    ConflictInLeaf {
        path: PathBuf,
        base_hash: Option<String>,
        target_hash: Option<String>,
        leaf_hash: Option<String>,
    },
}

// struct
#[derive(Debug, Clone)]
pub struct BrassIgnore {
    pub raw_patterns: Vec<String>,
    pub glob_set: GlobSet,
}

// impl
impl Default for BrassIgnore {
    // fn
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

// impl
impl BrassIgnore {
    // fn
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

    // fn
    pub fn is_ignored(&self, path: &Path) -> bool {
        self.glob_set.is_match(path)
    }
}

// struct
#[derive(Debug, Clone)]
pub struct Repository {
    pub worktree: PathBuf,
    pub brass_dir: PathBuf,
    pub ignore: BrassIgnore,
    pub config: BrassConfig,
    pub acl: AclConfig,
}

// impl
impl Repository {
    // fn
    pub fn init(path: &Path) -> std::io::Result<Self> {
        let brass_dir = path.join(".brass_control");

        fs::create_dir_all(brass_dir.join("objects"))?;
        fs::create_dir_all(brass_dir.join("refs").join("heads"))?;
        fs::create_dir_all(brass_dir.join("refs").join("leaves"))?;

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

    // fn
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

    // fn
    pub fn read_object(&self, hash: &str) -> std::io::Result<BrassObject> {
        let obj_path = self.brass_dir.join("objects").join(&hash[..2]).join(&hash[2..]);
        let file = File::open(obj_path)?;
        let mut decoder = ZlibDecoder::new(file);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)?;

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

    // fn
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

    // fn
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

    // fn
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

    // fn
    pub fn list_leaves(&self) -> std::io::Result<Vec<String>> {
        let leaves_dir = self.brass_dir.join("refs").join("leaves");
        let mut result = Vec::new();

        if !leaves_dir.exists() {
            return Ok(result);
        }

        for user_entry in fs::read_dir(leaves_dir)? {
            let user_entry = user_entry?;
            if user_entry.file_type()?.is_dir() {
                let user_name = user_entry.file_name().to_string_lossy().to_string();
                for leaf_entry in fs::read_dir(user_entry.path())? {
                    let leaf_entry = leaf_entry?;
                    if leaf_entry.file_type()?.is_file() {
                        let leaf_name = leaf_entry.file_name().to_string_lossy().to_string();
                        result.push(format!("{}/{}", user_name, leaf_name));
                    }
                }
            }
        }
        Ok(result)
    }

    // fn
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

        for path in all_paths {
            let base_h = base_map.get(&path).cloned();
            let target_h = target_map.get(&path).cloned();
            let leaf_h = leaf_map.get(&path).cloned();

            if leaf_h != base_h {
                if !self.acl.can_write(&self.config.user_name, &path) {
                    return Ok(LeafMergeResult::PermissionDenied {
                        user: self.config.user_name.clone(),
                              forbidden_path: path,
                    });
                }
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
                return Ok(LeafMergeResult::ConflictInLeaf {
                    path,
                    base_hash: base_h,
                    target_hash: target_h,
                    leaf_hash: leaf_h,
                });
            }
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

    // fn
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
        self.scan_worktree(&self.worktree, Path::new(""), index, &mut unstaged_entries, &mut untracked)?;

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

    // fn
    fn scan_worktree(
        &self,
        base_dir: &Path,
        rel_dir: &Path,
        index: &Index,
        unstaged: &mut Vec<(PathBuf, &'static str)>,
                     untracked: &mut Vec<PathBuf>,
    ) -> std::io::Result<()> {
        let current_dir = base_dir.join(rel_dir);
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let rel_path = rel_dir.join(file_name);

            if self.ignore.is_ignored(&rel_path) {
                continue;
            }

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.scan_worktree(base_dir, &rel_path, index, unstaged, untracked)?;
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
        Ok(())
    }

    // fn
    fn flatten_tree_from_commit(&self, commit_hash: &str) -> std::io::Result<HashMap<PathBuf, String>> {
        let mut result = HashMap::new();
        if let Ok(BrassObject::Commit(commit)) = self.read_object(commit_hash) {
            self.collect_tree_entries(&commit.tree_hash, Path::new(""), &mut result)?;
        }
        Ok(result)
    }

    // fn
    fn collect_tree_entries(&self, tree_hash: &str, prefix: &Path, map: &mut HashMap<PathBuf, String>) -> std::io::Result<()> {
        if let Ok(BrassObject::Tree(tree)) = self.read_object(tree_hash) {
            for entry in tree.entries {
                let path = prefix.join(&entry.name);
                if entry.mode == FileMode::Directory {
                    self.collect_tree_entries(&entry.hash, &path, map)?;
                } else {
                    map.insert(path, entry.hash);
                }
            }
        }
        Ok(())
    }

    // fn
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

    // fn
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

    // fn
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

// impl
impl BrassObject {
    // fn
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

// impl
impl Tree {
    // fn
    pub fn serialize_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            let line = format!("{:?} {}\0{}\n", entry.mode, entry.name, entry.hash);
            buf.extend_from_slice(line.as_bytes());
        }
        buf
    }

    // fn
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

// impl
impl Commit {
    // fn
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

    // fn
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
                    committer.email = email.trim_end_matches('>').to_string();
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

// impl
impl Index {
    // fn
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

    // fn
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

// impl
impl BrassConfig {
    // fn
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    // fn
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let xml_str = to_string(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, xml_str)
    }
}

// fn
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
                    Ok(LeafMergeResult::ConflictInLeaf { path, .. }) => {
                        eprintln!("Konflikt scalania w pliku: {:?}", path);
                    }
                    Err(e) => eprintln!("Błąd podczas scalania Liścia: {}", e),
                },
            }
        }
    }
}
