-- Database initialization script for Verifiable RDS AVS
-- Creates sample tables for testing the verification system

-- Enable deterministic ordering for verification consistency
SET enable_hashjoin = OFF;
SET enable_mergejoin = ON;
SET enable_nestloop = ON;
SET enable_parallel_query = OFF;
SET random_page_cost = 1.0;

-- Create extension for UUID generation (will be replaced by deterministic version in proxy)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create posts table
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    author_id INTEGER NOT NULL REFERENCES users(id),
    published BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create comments table
CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    author_id INTEGER NOT NULL REFERENCES users(id),
    post_id INTEGER NOT NULL REFERENCES posts(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create tags table
CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

-- Create posts_tags table for many-to-many relationship
CREATE TABLE IF NOT EXISTS posts_tags (
    post_id INTEGER NOT NULL REFERENCES posts(id),
    tag_id INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (post_id, tag_id)
);

-- Create verification_blocks table to store block information
CREATE TABLE IF NOT EXISTS verification_blocks (
    block_number BIGINT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    state_root VARCHAR(66) NOT NULL,
    previous_block_number BIGINT,
    previous_state_root VARCHAR(66),
    operator_address VARCHAR(42) NOT NULL,
    operator_signature VARCHAR(132) NOT NULL,
    FOREIGN KEY (previous_block_number) REFERENCES verification_blocks(block_number)
);

-- Create verification_transactions table to store transaction information
CREATE TABLE IF NOT EXISTS verification_transactions (
    tx_id BIGSERIAL PRIMARY KEY,
    block_number BIGINT NOT NULL,
    query TEXT NOT NULL,
    query_fingerprint VARCHAR(66) NOT NULL,
    pre_state_root VARCHAR(66) NOT NULL,
    post_state_root VARCHAR(66) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (block_number) REFERENCES verification_blocks(block_number)
);

-- Create verification_merkle_trees table to store Merkle tree information
CREATE TABLE IF NOT EXISTS verification_merkle_trees (
    table_name VARCHAR(100) NOT NULL,
    block_number BIGINT NOT NULL,
    merkle_root VARCHAR(66) NOT NULL,
    schema_version INTEGER NOT NULL,
    PRIMARY KEY (table_name, block_number),
    FOREIGN KEY (block_number) REFERENCES verification_blocks(block_number)
);

-- Create verification_challenges table to store challenge information
CREATE TABLE IF NOT EXISTS verification_challenges (
    challenge_id BIGSERIAL PRIMARY KEY,
    block_number BIGINT NOT NULL,
    transaction_id BIGINT,
    challenger_address VARCHAR(42) NOT NULL,
    bond_amount VARCHAR(78) NOT NULL,
    challenge_type VARCHAR(50) NOT NULL,
    evidence TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP,
    FOREIGN KEY (block_number) REFERENCES verification_blocks(block_number),
    FOREIGN KEY (transaction_id) REFERENCES verification_transactions(tx_id)
);

-- Insert sample data
INSERT INTO users (username, email, password_hash) VALUES
    ('alice', 'alice@example.com', 'hash1'),
    ('bob', 'bob@example.com', 'hash2'),
    ('charlie', 'charlie@example.com', 'hash3');

INSERT INTO posts (title, content, author_id, published) VALUES
    ('First Post', 'This is the first post content.', 1, TRUE),
    ('Second Post', 'This is the second post content.', 1, TRUE),
    ('Draft Post', 'This is a draft post.', 2, FALSE);

INSERT INTO comments (content, author_id, post_id) VALUES
    ('Great post!', 2, 1),
    ('I agree!', 3, 1),
    ('Looking forward to more.', 2, 2);

INSERT INTO tags (name) VALUES
    ('technology'),
    ('programming'),
    ('database'),
    ('verification');

INSERT INTO posts_tags (post_id, tag_id) VALUES
    (1, 1),
    (1, 2),
    (2, 1),
    (2, 3),
    (3, 2),
    (3, 4);

-- Initialize the first verification block (genesis block)
INSERT INTO verification_blocks (
    block_number, 
    timestamp, 
    state_root, 
    previous_block_number, 
    previous_state_root, 
    operator_address, 
    operator_signature
) VALUES (
    0, 
    NOW(), 
    '0x0000000000000000000000000000000000000000000000000000000000000000', 
    NULL, 
    NULL, 
    '0x0000000000000000000000000000000000000000', 
    '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
); 