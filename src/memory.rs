use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;

pub struct MemoryStore {
    conn: Connection,
}

#[derive(Clone, Debug)]
pub struct MemoryItem {
    pub id: i64,
    pub kind: String,
    pub source: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MemoryKindCount {
    pub kind: String,
    pub count: usize,
}

impl MemoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating memory database directory")?;
        }
        let conn = Connection::open(path).context("opening memory database")?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory database")?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn remember(&self, kind: &str, source: &str, content: &str) -> Result<i64> {
        let content = content.trim();
        if content.is_empty() {
            return Ok(0);
        }
        self.conn.execute(
            "INSERT INTO memory(kind, source, content) VALUES (?1, ?2, ?3)",
            params![kind, source, content],
        )?;
        let id = self.conn.last_insert_rowid();
        self.conn.execute(
            "INSERT INTO memory_fts(rowid, kind, source, content) VALUES (?1, ?2, ?3, ?4)",
            params![id, kind, source, content],
        )?;
        Ok(id)
    }

    pub fn remember_document(&self, source: &str, text: &str, chunk_bytes: usize) -> Result<usize> {
        let mut count = 0;
        for chunk in chunk_document(text, chunk_bytes.max(1)) {
            self.remember("document", source, &chunk)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<MemoryItem>> {
        let limit = limit.max(1) as i64;
        let fts_query = fts_query(query);
        if fts_query.is_empty() {
            return self.latest(limit);
        }

        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.kind, m.source, m.content
             FROM memory_fts
             JOIN memory m ON m.id = memory_fts.rowid
             WHERE memory_fts MATCH ?1
             ORDER BY bm25(memory_fts)
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit], row_to_item)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading memory search results")
    }

    pub fn compact_context(&self, query: &str, max_bytes: usize) -> Result<String> {
        let mut out = String::new();
        for item in self.search(query, 8)? {
            let header = format!("[memory:{}:{}] ", item.kind, item.source);
            let remaining = max_bytes.saturating_sub(out.len() + header.len());
            if remaining == 0 {
                break;
            }
            let content = truncate_to_bytes(&item.content, remaining.saturating_sub(1));
            out.push_str(&header);
            out.push_str(&content);
            out.push('\n');
            if out.len() >= max_bytes {
                break;
            }
        }
        if out.len() > max_bytes {
            out.truncate(max_bytes);
        }
        Ok(out)
    }

    pub fn prune_to_latest(&self, keep: usize) -> Result<usize> {
        let keep = keep.max(1) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT id FROM memory
             WHERE id NOT IN (SELECT id FROM memory ORDER BY id DESC LIMIT ?1)",
        )?;
        let ids = stmt
            .query_map(params![keep], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for id in &ids {
            self.conn
                .execute("DELETE FROM memory_fts WHERE rowid = ?1", params![id])?;
            self.conn
                .execute("DELETE FROM memory WHERE id = ?1", params![id])?;
        }
        Ok(ids.len())
    }

    pub fn delete_kind(&self, kind: &str) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM memory WHERE kind = ?1 ORDER BY id")?;
        let ids = stmt
            .query_map(params![kind], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for id in &ids {
            self.conn
                .execute("DELETE FROM memory_fts WHERE rowid = ?1", params![id])?;
            self.conn
                .execute("DELETE FROM memory WHERE id = ?1", params![id])?;
        }
        Ok(ids.len())
    }

    pub fn latest_by_kind(&self, kind: &str, limit: usize) -> Result<Vec<MemoryItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, source, content
             FROM memory
             WHERE kind = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![kind, limit.max(1) as i64], row_to_item)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading memory items by kind")
    }

    pub fn kind_counts(&self) -> Result<Vec<MemoryKindCount>> {
        let mut stmt = self.conn.prepare(
            "SELECT kind, COUNT(*) as count
             FROM memory
             GROUP BY kind
             ORDER BY count DESC, kind ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MemoryKindCount {
                kind: row.get(0)?,
                count: row.get::<_, i64>(1)? as usize,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading memory kind counts")
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
            USING fts5(kind, source, content);",
        )?;
        Ok(())
    }

    fn latest(&self, limit: i64) -> Result<Vec<MemoryItem>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, source, content FROM memory ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit], row_to_item)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading latest memory")
    }
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryItem> {
    Ok(MemoryItem {
        id: row.get(0)?,
        kind: row.get(1)?,
        source: row.get(2)?,
        content: row.get(3)?,
    })
}

fn fts_query(query: &str) -> String {
    query
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .filter(|term| term.len() >= 2)
        .take(8)
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn truncate_to_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = 0;
    for (idx, _) in text.char_indices() {
        if idx <= max_bytes {
            end = idx;
        } else {
            break;
        }
    }
    let mut out = text[..end].to_string();
    out.push_str("...");
    out
}

fn chunk_document(text: &str, max_bytes: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for paragraph in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
        let needed = current.len() + paragraph.len() + 2;
        if !current.is_empty() && needed > max_bytes {
            chunks.push(current.trim().to_string());
            current.clear();
        }
        if !current.is_empty() {
            current.push_str("\n\n");
        }
        current.push_str(paragraph);
    }
    if !current.trim().is_empty() {
        chunks.push(current.trim().to_string());
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_recalls_saved_items_with_source_labels() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        store
            .remember("finding", "nmap", "OpenSSH 8.2p1 on port 22")
            .expect("memory insert");

        let results = store.search("OpenSSH", 5).expect("memory search");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source, "nmap");
        assert!(results[0].content.contains("OpenSSH 8.2p1"));
    }

    #[test]
    fn open_creates_parent_directory_for_public_default_memory_path() {
        let dir = std::env::temp_dir().join(format!("mietos-memory-test-{}", std::process::id()));
        let path = dir.join("nested").join("operator_memory.sqlite3");
        let _ = std::fs::remove_dir_all(&dir);

        let store = MemoryStore::open(&path).expect("memory store opens");
        drop(store);

        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_context_respects_byte_budget() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        store
            .remember("note", "terminal", &"A".repeat(500))
            .expect("memory insert");

        let context = store.compact_context("", 160).expect("compact context");

        assert!(context.len() <= 160);
        assert!(context.contains("[memory:"));
    }

    #[test]
    fn compact_context_does_not_panic_on_utf8_boundaries() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        store
            .remember("note", "terminal", &"poort открыт ".repeat(80))
            .expect("memory insert");

        let context = store
            .compact_context("poort", 155)
            .expect("compact context");

        assert!(context.is_char_boundary(context.len()));
        assert!(context.len() <= 155);
    }

    #[test]
    fn remember_document_chunks_and_searches_file_text() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        let text = "alpha service inventory\n\nbeta hidden directory /admin-panel\n";

        let chunks = store
            .remember_document("task-notes.md", text, 32)
            .expect("document ingest");
        let results = store.search("admin-panel", 5).expect("search document");

        assert!(chunks >= 2);
        assert_eq!(results[0].kind, "document");
        assert_eq!(results[0].source, "task-notes.md");
        assert!(results[0].content.contains("/admin-panel"));
    }

    #[test]
    fn memory_kind_counts_and_latest_by_kind_support_learning_view() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        store
            .remember("lesson", "run-a", "Use SIEM first")
            .expect("insert lesson");
        store
            .remember("finding", "nmap", "22/tcp open")
            .expect("insert finding");
        store
            .remember("lesson", "run-b", "Avoid web fuzzing on timeouts")
            .expect("insert lesson");

        let counts = store.kind_counts().expect("kind counts");
        let lessons = store.latest_by_kind("lesson", 5).expect("latest lessons");

        assert_eq!(counts[0].kind, "lesson");
        assert_eq!(counts[0].count, 2);
        assert_eq!(lessons[0].source, "run-b");
    }

    #[test]
    fn delete_kind_removes_memory_and_fts_rows() {
        let store = MemoryStore::open_in_memory().expect("memory store opens");
        store
            .remember("evidence", "terminal", "giant noisy scan output")
            .expect("insert evidence");
        store
            .remember("lesson", "run", "keep this")
            .expect("insert lesson");

        let deleted = store.delete_kind("evidence").expect("delete kind");
        let evidence = store.search("giant noisy scan output", 5).expect("search");
        let lessons = store.search("keep this", 5).expect("search");

        assert_eq!(deleted, 1);
        assert!(evidence.is_empty());
        assert_eq!(lessons.len(), 1);
    }
}
