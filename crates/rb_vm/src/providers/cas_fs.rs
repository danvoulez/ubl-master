use crate::exec::CasProvider;
use crate::types::Cid;
use blake3::Hasher;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// CAS baseado em filesystem usando BLAKE3, com paths sharded.
pub struct FsCas {
    root: PathBuf,
}

impl FsCas {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).ok();
        Self { root }
    }

    fn path_for(&self, cid: &Cid) -> PathBuf {
        // Espera formato "b3:<hex>"
        let s = cid.0.strip_prefix("b3:").unwrap_or(&cid.0);
        let (p1, p2) = s.split_at(2.min(s.len()));
        self.root.join(p1).join(p2)
    }
}

impl CasProvider for FsCas {
    fn put(&mut self, bytes: &[u8]) -> Cid {
        let mut hasher = Hasher::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let hex = hex::encode(digest.as_bytes());
        let cid = Cid(format!("b3:{hex}"));
        let path = self.path_for(&cid);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        if !path.exists() {
            let mut f = fs::File::create(&path).expect("cas create");
            f.write_all(bytes).expect("cas write");
        }
        cid
    }

    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        let path = self.path_for(cid);
        fs::read(path).ok()
    }
}
