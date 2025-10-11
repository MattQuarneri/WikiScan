-- Knowledge Base SQLite Schema
-- Multi-resolution knowledge representation system
-- Author: Generated for custom KB application
-- License: Use freely in your commercial application

-- ============================================================================
-- LAYER 1: RAW CONTENT (Source of Truth)
-- ============================================================================

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,              -- The original, full-fidelity content
    content_type TEXT DEFAULT 'text',   -- markdown, plain, html, code, etc.
    created_at INTEGER NOT NULL,        -- Unix timestamp
    updated_at INTEGER NOT NULL,        -- Unix timestamp
    deleted_at INTEGER,                 -- Soft delete (NULL = active)
    metadata TEXT,                      -- JSON: flexible custom fields
    version INTEGER DEFAULT 1           -- Version number for this message
);

CREATE INDEX idx_messages_created ON messages(created_at);
CREATE INDEX idx_messages_updated ON messages(updated_at);
CREATE INDEX idx_messages_deleted ON messages(deleted_at) WHERE deleted_at IS NULL;

-- Full-text search on message content
CREATE VIRTUAL TABLE messages_fts USING fts5(
    content,
    content=messages,
    content_rowid=rowid
);

-- Triggers to keep FTS in sync
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.rowid, new.content);
END;

CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
    UPDATE messages_fts SET content = new.content WHERE rowid = old.rowid;
END;

CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    DELETE FROM messages_fts WHERE rowid = old.rowid;
END;

-- ============================================================================
-- LAYER 2: FILES & BINARY DATA
-- ============================================================================

CREATE TABLE files (
    id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,            -- Relative or absolute path on disk
    file_name TEXT NOT NULL,            -- Original filename
    file_size INTEGER,                  -- Size in bytes
    mime_type TEXT NOT NULL,            -- e.g., image/png, application/pdf
    sha256_hash TEXT,                   -- File integrity verification
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,                 -- Soft delete
    metadata TEXT                       -- JSON: EXIF data, page count, etc.
);

CREATE INDEX idx_files_mime ON files(mime_type);
CREATE INDEX idx_files_hash ON files(sha256_hash);
CREATE INDEX idx_files_deleted ON files(deleted_at) WHERE deleted_at IS NULL;

-- File descriptions (especially for images, PDFs, videos)
CREATE TABLE file_descriptions (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    description TEXT NOT NULL,          -- Human or AI-generated description
    description_type TEXT DEFAULT 'caption',  -- caption, ocr, transcript, summary
    language TEXT DEFAULT 'en',
    confidence REAL,                    -- 0-1 for AI-generated content
    generated_by TEXT,                  -- Model name or 'human'
    created_at INTEGER NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX idx_file_descriptions_file ON file_descriptions(file_id);

-- Full-text search on file descriptions
CREATE VIRTUAL TABLE file_descriptions_fts USING fts5(
    description,
    content=file_descriptions,
    content_rowid=rowid
);

CREATE TRIGGER file_descriptions_fts_insert AFTER INSERT ON file_descriptions BEGIN
    INSERT INTO file_descriptions_fts(rowid, description) VALUES (new.rowid, new.description);
END;

CREATE TRIGGER file_descriptions_fts_update AFTER UPDATE ON file_descriptions BEGIN
    UPDATE file_descriptions_fts SET description = new.description WHERE rowid = old.rowid;
END;

CREATE TRIGGER file_descriptions_fts_delete AFTER DELETE ON file_descriptions BEGIN
    DELETE FROM file_descriptions_fts WHERE rowid = old.rowid;
END;

-- Link files to messages
CREATE TABLE message_files (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    attachment_order INTEGER DEFAULT 0,  -- Order of attachments in message
    created_at INTEGER NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX idx_message_files_message ON message_files(message_id);
CREATE INDEX idx_message_files_file ON message_files(file_id);

-- ============================================================================
-- LAYER 3: EXTRACTED ENTITIES & CONCEPTS
-- ============================================================================

CREATE TABLE entities (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,          -- concept, person, place, idea, thought, topic, etc.
    canonical_name TEXT NOT NULL,       -- Normalized name/title
    description TEXT,                   -- Optional longer description
    confidence REAL DEFAULT 1.0,        -- 0-1: extraction confidence
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    metadata TEXT                       -- JSON: additional structured data
);

CREATE INDEX idx_entities_type ON entities(entity_type);
CREATE INDEX idx_entities_name ON entities(canonical_name);

-- Full-text search on entities
CREATE VIRTUAL TABLE entities_fts USING fts5(
    canonical_name,
    description,
    content=entities,
    content_rowid=rowid
);

CREATE TRIGGER entities_fts_insert AFTER INSERT ON entities BEGIN
    INSERT INTO entities_fts(rowid, canonical_name, description) 
    VALUES (new.rowid, new.canonical_name, new.description);
END;

CREATE TRIGGER entities_fts_update AFTER UPDATE ON entities BEGIN
    UPDATE entities_fts 
    SET canonical_name = new.canonical_name, description = new.description 
    WHERE rowid = old.rowid;
END;

CREATE TRIGGER entities_fts_delete AFTER DELETE ON entities BEGIN
    DELETE FROM entities_fts WHERE rowid = old.rowid;
END;

-- Link entities back to their source messages with exact spans
CREATE TABLE message_entities (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    span_start INTEGER,                 -- Character offset in message content
    span_end INTEGER,                   -- Character offset (exclusive)
    context TEXT,                       -- Surrounding text snippet for display
    extraction_method TEXT,             -- 'manual', 'nlp', 'llm', etc.
    confidence REAL DEFAULT 1.0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE INDEX idx_message_entities_message ON message_entities(message_id);
CREATE INDEX idx_message_entities_entity ON message_entities(entity_id);

-- Link entities to files (e.g., faces in photos, topics in PDFs)
CREATE TABLE file_entities (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    bounding_box TEXT,                  -- JSON: coordinates for images/videos
    page_number INTEGER,                -- For PDFs, documents
    confidence REAL DEFAULT 1.0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE
);

CREATE INDEX idx_file_entities_file ON file_entities(file_id);
CREATE INDEX idx_file_entities_entity ON file_entities(entity_id);

-- ============================================================================
-- LAYER 4: EMBEDDINGS (Vector Representations)
-- ============================================================================

CREATE TABLE embeddings (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,            -- References message, entity, file, or derived_content
    source_type TEXT NOT NULL,          -- 'message', 'entity', 'summary', 'file_description', etc.
    embedding BLOB NOT NULL,            -- Serialized vector (use numpy/array format)
    model_name TEXT NOT NULL,           -- e.g., 'text-embedding-3-small', 'all-MiniLM-L6-v2'
    dimension INTEGER NOT NULL,         -- Vector dimensions (e.g., 384, 1536)
    created_at INTEGER NOT NULL,
    metadata TEXT                       -- JSON: model version, parameters, etc.
);

CREATE INDEX idx_embeddings_source ON embeddings(source_id, source_type);
CREATE INDEX idx_embeddings_model ON embeddings(model_name);

-- Note: For efficient vector similarity search, consider:
-- 1. sqlite-vss extension (FAISS-based)
-- 2. External in-memory index (hnswlib, faiss)
-- 3. Separate vector database (Qdrant, Weaviate) with sync

-- ============================================================================
-- LAYER 5: DERIVED CONTENT (Summaries, Expansions, Transformations)
-- ============================================================================

CREATE TABLE derived_content (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,            -- Usually a message_id, but could be entity or file
    source_type TEXT DEFAULT 'message', -- 'message', 'entity', 'file'
    derivation_type TEXT NOT NULL,      -- 'summary', 'expansion', 'translation', 'outline', etc.
    content TEXT NOT NULL,              -- The derived text
    generation_prompt TEXT,             -- Prompt used (for reproducibility)
    model_used TEXT,                    -- Model that generated this
    language TEXT DEFAULT 'en',         -- For translations
    created_at INTEGER NOT NULL,
    metadata TEXT,                      -- JSON: additional parameters
    FOREIGN KEY (source_id) REFERENCES messages(id) ON DELETE CASCADE
);

CREATE INDEX idx_derived_source ON derived_content(source_id, source_type);
CREATE INDEX idx_derived_type ON derived_content(derivation_type);

-- Full-text search on derived content
CREATE VIRTUAL TABLE derived_content_fts USING fts5(
    content,
    content=derived_content,
    content_rowid=rowid
);

CREATE TRIGGER derived_content_fts_insert AFTER INSERT ON derived_content BEGIN
    INSERT INTO derived_content_fts(rowid, content) VALUES (new.rowid, new.content);
END;

CREATE TRIGGER derived_content_fts_update AFTER UPDATE ON derived_content BEGIN
    UPDATE derived_content_fts SET content = new.content WHERE rowid = old.rowid;
END;

CREATE TRIGGER derived_content_fts_delete AFTER DELETE ON derived_content BEGIN
    DELETE FROM derived_content_fts WHERE rowid = old.rowid;
END;

-- ============================================================================
-- LAYER 6: RELATIONSHIPS (Knowledge Graph)
-- ============================================================================

CREATE TABLE relationships (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,            -- Can reference any content type
    source_type TEXT NOT NULL,          -- 'message', 'entity', 'file', etc.
    target_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    relationship_type TEXT NOT NULL,    -- 'links_to', 'contradicts', 'supports', 
                                        -- 'derives_from', 'mentions', 'similar_to', etc.
    strength REAL DEFAULT 1.0,          -- 0-1: confidence or weight
    evidence_span TEXT,                 -- Text excerpt supporting this relationship
    bidirectional INTEGER DEFAULT 0,    -- Boolean: is relationship symmetric?
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    metadata TEXT                       -- JSON: additional relationship properties
);

CREATE INDEX idx_relationships_source ON relationships(source_id, source_type);
CREATE INDEX idx_relationships_target ON relationships(target_id, target_type);
CREATE INDEX idx_relationships_type ON relationships(relationship_type);

-- ============================================================================
-- LAYER 7: TAGS & CATEGORIZATION
-- ============================================================================

CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    color TEXT,                         -- Hex color for UI
    description TEXT,
    created_at INTEGER NOT NULL,
    metadata TEXT                       -- JSON: icon, parent_tag_id, etc.
);

CREATE INDEX idx_tags_name ON tags(name);

-- Many-to-many: items can have multiple tags
CREATE TABLE tagged_items (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,              -- References any content type
    item_type TEXT NOT NULL,            -- 'message', 'entity', 'file', etc.
    tag_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE INDEX idx_tagged_items_item ON tagged_items(item_id, item_type);
CREATE INDEX idx_tagged_items_tag ON tagged_items(tag_id);

-- ============================================================================
-- LAYER 8: VERSION HISTORY & SYNC
-- ============================================================================

-- Track all changes for sync and versioning
CREATE TABLE change_log (
    id TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id TEXT NOT NULL,
    operation TEXT NOT NULL,            -- 'insert', 'update', 'delete'
    changed_data TEXT,                  -- JSON: what changed
    device_id TEXT,                     -- Which device made the change
    user_id TEXT,                       -- Which user (for multi-user)
    timestamp INTEGER NOT NULL,         -- When change occurred
    vector_clock TEXT,                  -- JSON: for conflict resolution (CRDT)
    synced INTEGER DEFAULT 0            -- Boolean: has this been synced?
);

CREATE INDEX idx_change_log_table ON change_log(table_name, record_id);
CREATE INDEX idx_change_log_timestamp ON change_log(timestamp);
CREATE INDEX idx_change_log_synced ON change_log(synced) WHERE synced = 0;

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- View: All content with their entity connections
CREATE VIEW content_entities AS
SELECT 
    m.id as content_id,
    'message' as content_type,
    m.content,
    m.created_at,
    e.id as entity_id,
    e.entity_type,
    e.canonical_name,
    me.confidence
FROM messages m
LEFT JOIN message_entities me ON m.id = me.message_id
LEFT JOIN entities e ON me.entity_id = e.id
WHERE m.deleted_at IS NULL;

-- View: Knowledge graph with readable labels
CREATE VIEW knowledge_graph AS
SELECT 
    r.id,
    r.source_id,
    r.source_type,
    r.target_id,
    r.target_type,
    r.relationship_type,
    r.strength,
    r.bidirectional
FROM relationships r;

-- View: Files with descriptions
CREATE VIEW files_with_descriptions AS
SELECT 
    f.id as file_id,
    f.file_name,
    f.mime_type,
    f.file_path,
    fd.description,
    fd.description_type,
    fd.confidence
FROM files f
LEFT JOIN file_descriptions fd ON f.id = fd.file_id
WHERE f.deleted_at IS NULL;

-- ============================================================================
-- EXAMPLE QUERIES
-- ============================================================================

-- Find similar content using embeddings (pseudo-code, needs vector search)
-- SELECT source_id FROM embeddings WHERE cosine_similarity(embedding, ?) > 0.8;

-- Traverse knowledge graph (find all connected entities within 3 hops)
-- WITH RECURSIVE connected(id, depth) AS (
--   SELECT target_id, 0 FROM relationships WHERE source_id = ? AND source_type = 'entity'
--   UNION
--   SELECT r.target_id, c.depth + 1 
--   FROM relationships r 
--   JOIN connected c ON r.source_id = c.id 
--   WHERE c.depth < 3 AND r.source_type = 'entity'
-- )
-- SELECT DISTINCT e.* FROM connected c JOIN entities e ON c.id = e.id;

-- Full-text search across all content
-- SELECT * FROM messages WHERE id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?);

-- Find all messages with a specific entity
-- SELECT m.* FROM messages m
-- JOIN message_entities me ON m.id = me.message_id
-- JOIN entities e ON me.entity_id = e.id
-- WHERE e.canonical_name = 'Artificial Intelligence';