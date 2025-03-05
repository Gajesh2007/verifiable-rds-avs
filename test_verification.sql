-- This script tests the verification functionality with a series of commands
-- and checks the verification tables for records

-- First, let's check the current state of verification tables
\echo 'Current Verification Configuration:'
\echo '=================================='
SELECT verification_version();
SELECT verification_state_root();

-- Check verification blocks
\echo '\nVerification Blocks:'
\echo '==================='
SELECT * FROM verification_blocks ORDER BY block_number DESC LIMIT 5;

-- Check current verification records
\echo '\nCurrent Verification Transactions:'
\echo '================================='
SELECT transaction_id, query_type, verification_status, array_to_string(modified_tables, ', ') as tables, 
       substr(query, 1, 50) as query_preview
FROM verification_transactions 
ORDER BY timestamp DESC LIMIT 5;

-- Insert a new test record
\echo '\nInserting test record through proxy...'
INSERT INTO test_table (id, name) VALUES (9, 'verification_test_proxy');

-- Check for new verification record (should appear if proxy is working correctly)
\echo '\nVerification Transactions After Insert:'
\echo '======================================'
SELECT transaction_id, query_type, verification_status, array_to_string(modified_tables, ', ') as tables, 
       substr(query, 1, 50) as query_preview
FROM verification_transactions 
ORDER BY timestamp DESC LIMIT 5;

-- Update test to see if modifications are tracked
\echo '\nUpdating test record through proxy...'
UPDATE test_table SET name = 'verification_updated' WHERE id = 9;

-- Check for UPDATE verification record
\echo '\nVerification Transactions After Update:'
\echo '======================================'
SELECT transaction_id, query_type, verification_status, array_to_string(modified_tables, ', ') as tables, 
       substr(query, 1, 50) as query_preview
FROM verification_transactions 
ORDER BY timestamp DESC LIMIT 5;

-- Check merkle trees
\echo '\nMerkle Trees:'
\echo '============='
SELECT * FROM verification_merkle_trees ORDER BY created_at DESC LIMIT 5;

-- Final verification status
\echo '\nVerification System Status:'
\echo '=========================='
SELECT verification_state_root(); 