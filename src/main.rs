// importy
use flate2::write::ZlibEncoder;
use flate2::Compression;
use globset::{Glob, GlobSet, GlobSetBuilder};
use quick_xml::de::from_str;
use quick_xml::se::to_string;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadTarget {
    Symbolic(String),
    Direct(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub name: String,
    pub target_commit_hash: String,
}

#[derive(Debug, Clone)]
pub struct Repository {
    pub worktree: PathBuf,
    pub brass_dir: PathBuf,
    pub ignore: BrassIgnore,
    pub config: BrassConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Unmodified,
    Staged,
    Modified,
    Untracked,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingTreeStatus {
    pub staged: HashMap<PathBuf, IndexEntry>,
    pub unstaged: HashMap<PathBuf, IndexEntry>,
    pub untracked: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "brass_config")]
pub struct BrassConfig {
    pub user_name: String,
    pub user_email: String,
    pub default_branch: String,
}

#[derive(Debug, Clone)]
pub struct BrassIgnore {
    pub raw_patterns: Vec<String>,
    pub glob_set: GlobSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Keep(String),
    Insert(String),
    Delete(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub path: PathBuf,
    pub operation: Vec<DiffOp>,
}

// impl
impl Repository {
    pub fn init(path: &Path) -> std::io::Result<Self> {
        let brass_dir = path.join(".brass_control");

        fs::create_dir_all(brass_dir.join("objects"))?;
        fs::create_dir_all(brass_dir.join("refs").join("heads"))?;

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

        let ignore_path = path.join(".brass_control_ignore");
        let ignore = BrassIgnore::load(&ignore_path);

        Ok(Self {
            worktree: path.to_path_buf(),
           brass_dir,
           ignore,
           config,
        })
    }

    pub fn write_object(&self, object: &BrassObject) -> std::io::Result<String> {
        let (hash, uncompressed_data) = object.serialize();

        let dir_name = &hash[..2];
        let file_name = &hash[2..];

        let obj_dir = self.brass_dir.join("objects").join(dir_name);
        fs::create_dir_all(&obj_dir)?;

        let obj_path = obj_dir.join(file_name);
        if !obj_path.exists() {
            let file = File::create(obj_path)?;
            let mut encoder = ZlibEncoder::new(file, Compression::default());
            encoder.write_all(&uncompressed_data)?;
        }

        Ok(hash)
    }

    pub fn add(&self, relative_path: &Path, index: &mut Index) -> std::io::Result<()> {
        if self.ignore.is_ignored(relative_path) {
            return Ok(());
        }

        let full_path = self.worktree.join(relative_path);
        let data = fs::read(&full_path)?;
        let metadata = fs::metadata(&full_path)?;

        let blob = BrassObject::Blob(Blob { data });
        let blob_hash = self.write_object(&blob)?;

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

    pub fn commit(
        &self,
        message: String,
        author: Signature,
        index: &Index,
    ) -> std::io::Result<String> {
        let mut tree_entries = Vec::new();
        for entry in &index.entries {
            tree_entries.push(TreeEntry {
                mode: entry.mode,
                name: entry.path.to_string_lossy().to_string(),
                              hash: entry.hash.clone(),
            });
        }

        let root_tree = BrassObject::Tree(Tree { entries: tree_entries });
        let tree_hash = self.write_object(&root_tree)?;

        let parent_hash = self.get_head_commit_hash().ok();
        let parent_hashes = parent_hash.into_iter().collect();

        let commit = BrassObject::Commit(Commit {
            tree_hash,
            parent_hashes,
            author: author.clone(),
                                         committer: author,
                                         message,
        });

        let commit_hash = self.write_object(&commit)?;

        self.update_head_target(&commit_hash)?;

        Ok(commit_hash)
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
        let hash = format!("{:x}", hasher.finalize());

        (hash, ful_data)
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
}

impl BrassConfig {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let xml_str = to_string(self)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, xml_str)
    }
}

impl Default for BrassConfig {
    fn default() -> Self {
        Self {
            user_name: String::from("Anonymous"),
            user_email: String::from("user@localhost"),
            default_branch: String::from("main"),
        }
    }
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

        let default_rules = [
            ".brass_control/**",
            "**/.brass_control/**",
            ".brass_control_ignore",
        ];

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

        let glob_set = builder.build().unwrap_or_else(|_| GlobSet::empty());

        Self {
            raw_patterns,
            glob_set,
        }
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        self.glob_set.is_match(path)
    }
}

fn main() {
    println!("Hello, world!");
}
