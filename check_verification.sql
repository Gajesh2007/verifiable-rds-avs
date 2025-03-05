-- Check if verification service is active
SELECT pg_sleep(1); -- Give a second to check logs

-- Check for existing verification configuration
\echo 'Current Verification State:'
\echo '=========================='
SELECT verification_version();
SELECT verification_state_root();

-- Check verification blocks
\echo '\nVerification Blocks:'
\echo '==================='
SELECT * FROM verification_blocks ORDER BY block_number DESC LIMIT 5;

-- Initialize verification if needed
\echo '\nInitializing verification system...'
BEGIN;
-- First, check if we need to initialize the verification block with a non-zero block number
INSERT INTO verification_blocks (block_number, timestamp, state_root, previous_block_number, previous_state_root, operator_address, operator_signature)
SELECT 1, NOW(), '0x' || md5(random()::text)::text, 0, '0x0000000000000000000000000000000000000000000000000000000000000000', 
       '0x' || substr(md5(random()::text), 1, 40), '0x' || md5(random()::text) || md5(random()::text) || md5(random()::text)
WHERE NOT EXISTS (SELECT 1 FROM verification_blocks WHERE block_number > 0);

-- Force a verification transaction for our test insert
INSERT INTO verification_transactions 
(query, query_type, pre_state_root, post_state_root, timestamp, modified_tables, verification_status)
VALUES 
('INSERT INTO test_table (id, name) VALUES (6, ''verification_test'');', 
 'INSERT', '0x' || md5(random()::text)::text, '0x' || md5(random()::text)::text, 
 NOW(), ARRAY['test_table'], 'VERIFIED');

-- Initialize merkle tree entry
INSERT INTO verification_merkle_trees 
(table_name, root_hash, node_count, created_at, transaction_id)
VALUES 
('test_table', '0x' || md5(random()::text)::text, 1, NOW(), 
 (SELECT transaction_id FROM verification_transactions ORDER BY timestamp DESC LIMIT 1));
COMMIT;

-- Check verification transactions after initialization
\echo '\nVerification Transactions After Initialization:'
\echo '============================================='
SELECT * FROM verification_transactions ORDER BY timestamp DESC LIMIT 5;

-- Check merkle trees after initialization
\echo '\nMerkle Trees After Initialization:'
\echo '================================'
SELECT * FROM verification_merkle_trees ORDER BY created_at DESC LIMIT 5;

-- Test verification with a new insert
\echo '\nTesting verification with new INSERT...'
INSERT INTO test_table (id, name) VALUES (7, 'second_verification_test');

-- Check if it was recorded
\echo '\nVerification transactions after new INSERT:'
\echo '=========================================='
SELECT * FROM verification_transactions ORDER BY timestamp DESC LIMIT 5; 