use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tantivy::{
    collector::TopDocs,
    directory::MmapDirectory,
    doc,
    query::QueryParser,
    schema::{Field, IndexRecordOption, Schema, Value, STORED, STRING, TEXT},
    Index, IndexReader, IndexWriter, TantivyDocument, Term,
};
use tokio::sync::Mutex;

pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: Arc<Mutex<IndexWriter>>,
    id_field: Field,
    content_field: Field,
    account_id_field: Field,
}

impl SearchIndex {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let index_dir = data_dir.join("search_index");
        std::fs::create_dir_all(&index_dir)?;

        let mut schema_builder = Schema::builder();
        let id_field = schema_builder.add_text_field("id", STRING | STORED);
        let content_field = schema_builder.add_text_field("content", TEXT);
        let account_id_field = schema_builder.add_text_field("account_id", STRING | STORED);
        let schema = schema_builder.build();

        let dir = MmapDirectory::open(&index_dir)?;
        let index = Index::open_or_create(dir, schema)?;
        let reader = index.reader()?;
        let writer = index.writer(50_000_000)?; // 50MB heap

        Ok(Self {
            index,
            reader,
            writer: Arc::new(Mutex::new(writer)),
            id_field,
            content_field,
            account_id_field,
        })
    }

    pub async fn index_post(&self, post_id: i64, content: &str, account_id: i64) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let id_term = Term::from_field_text(self.id_field, &post_id.to_string());
        writer.delete_term(id_term);
        writer.add_document(doc!(
            self.id_field => post_id.to_string(),
            self.content_field => content,
            self.account_id_field => account_id.to_string(),
        ))?;
        writer.commit()?;
        Ok(())
    }

    pub async fn delete_post(&self, post_id: i64) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let id_term = Term::from_field_text(self.id_field, &post_id.to_string());
        writer.delete_term(id_term);
        writer.commit()?;
        Ok(())
    }

    pub fn search(&self, query_str: &str, limit: usize) -> Result<Vec<i64>> {
        self.reader.reload()?;
        let searcher = self.reader.searcher();
        let query_parser = QueryParser::for_index(&self.index, vec![self.content_field]);
        let query = query_parser.parse_query(query_str).unwrap_or_else(|_| {
            // Fallback: treat entire input as a term query
            Box::new(tantivy::query::TermQuery::new(
                Term::from_field_text(self.content_field, query_str),
                IndexRecordOption::Basic,
            ))
        });

        let top_docs = searcher.search(&query, &TopDocs::with_limit(limit))?;

        let mut ids = Vec::new();
        for (_score, doc_addr) in top_docs {
            let doc: TantivyDocument = searcher.doc(doc_addr)?;
            if let Some(id_val) = doc.get_first(self.id_field) {
                if let Some(id_str) = id_val.as_str() {
                    if let Ok(id) = id_str.parse::<i64>() {
                        ids.push(id);
                    }
                }
            }
        }
        Ok(ids)
    }

    /// Reindex all posts from the database
    pub async fn reindex_all(&self, pool: &sqlx::SqlitePool) -> Result<usize> {
        let posts: Vec<(i64, String, i64)> =
            sqlx::query_as("SELECT id, content, account_id FROM posts ORDER BY id")
                .fetch_all(pool)
                .await?;

        let mut writer = self.writer.lock().await;
        writer.delete_all_documents()?;

        let count = posts.len();
        for (id, content, account_id) in posts {
            writer.add_document(doc!(
                self.id_field => id.to_string(),
                self.content_field => content,
                self.account_id_field => account_id.to_string(),
            ))?;
        }
        writer.commit()?;
        drop(writer);
        self.reader.reload()?;

        Ok(count)
    }
}
