-- Code Manager Database Schema
-- Run this SQL in your PostgreSQL database (Supabase, Neon, etc.)

CREATE TABLE IF NOT EXISTS code_snippets (
    id BIGINT PRIMARY KEY,
    title TEXT NOT NULL,
    code TEXT NOT NULL,
    password TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    hidden BOOLEAN DEFAULT FALSE,
    is_encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_code_snippets_id ON code_snippets(id DESC);

-- Future-ready columns for images and PDFs (optional, uncomment when needed)
-- ALTER TABLE code_snippets ADD COLUMN content_type VARCHAR(50) DEFAULT 'code';
-- ALTER TABLE code_snippets ADD COLUMN file_url TEXT;
-- ALTER TABLE code_snippets ADD COLUMN file_name TEXT;
-- ALTER TABLE code_snippets ADD COLUMN file_mime_type VARCHAR(100);
-- ALTER TABLE code_snippets ADD COLUMN file_size BIGINT;
