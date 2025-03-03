//! Database row representation
//!
//! This module provides data structures for representing rows in a database table.

use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::crypto;
use super::domains;

/// Type of value in a row
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    /// Integer (32-bit)
    Integer,
    
    /// Big integer (64-bit)
    BigInt,
    
    /// Floating point (64-bit)
    Float,
    
    /// Text string
    Text,
    
    /// Binary data
    Binary,
    
    /// Boolean
    Boolean,
    
    /// UUID
    Uuid,
    
    /// Timestamp
    Timestamp,
    
    /// JSON data
    Json,
    
    /// Null value
    Null,
}

/// Value in a row
#[derive(Clone, Serialize, Deserialize)]
pub enum Value {
    /// Integer (32-bit)
    Integer(i32),
    
    /// Big integer (64-bit)
    BigInt(i64),
    
    /// Floating point (64-bit)
    Float(f64),
    
    /// Text string
    Text(String),
    
    /// Binary data
    Binary(Vec<u8>),
    
    /// Boolean
    Boolean(bool),
    
    /// UUID
    Uuid(Uuid),
    
    /// Timestamp (as milliseconds since Unix epoch)
    Timestamp(i64),
    
    /// JSON data
    Json(String),
    
    /// Null value
    Null,
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Value::Integer(v) => write!(f, "Integer({})", v),
            Value::BigInt(v) => write!(f, "BigInt({})", v),
            Value::Float(v) => write!(f, "Float({})", v),
            Value::Text(v) => {
                if v.len() > 20 {
                    write!(f, "Text(\"{}...\")", &v[0..20])
                } else {
                    write!(f, "Text(\"{}\")", v)
                }
            }
            Value::Binary(v) => {
                if v.len() > 10 {
                    write!(f, "Binary({} bytes)", v.len())
                } else {
                    write!(f, "Binary({:?})", v)
                }
            }
            Value::Boolean(v) => write!(f, "Boolean({})", v),
            Value::Uuid(v) => write!(f, "Uuid({})", v),
            Value::Timestamp(v) => write!(f, "Timestamp({})", v),
            Value::Json(v) => {
                if v.len() > 20 {
                    write!(f, "Json({}...)", &v[0..20])
                } else {
                    write!(f, "Json({})", v)
                }
            }
            Value::Null => write!(f, "Null"),
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Integer(a), Value::Integer(b)) => a == b,
            (Value::BigInt(a), Value::BigInt(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => {
                // Special handling for NaN
                if a.is_nan() && b.is_nan() {
                    true
                } else {
                    a == b
                }
            }
            (Value::Text(a), Value::Text(b)) => a == b,
            (Value::Binary(a), Value::Binary(b)) => a == b,
            (Value::Boolean(a), Value::Boolean(b)) => a == b,
            (Value::Uuid(a), Value::Uuid(b)) => a == b,
            (Value::Timestamp(a), Value::Timestamp(b)) => a == b,
            (Value::Json(a), Value::Json(b)) => a == b,
            (Value::Null, Value::Null) => true,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Value {
    /// Get the type of the value
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::Integer(_) => ValueType::Integer,
            Value::BigInt(_) => ValueType::BigInt,
            Value::Float(_) => ValueType::Float,
            Value::Text(_) => ValueType::Text,
            Value::Binary(_) => ValueType::Binary,
            Value::Boolean(_) => ValueType::Boolean,
            Value::Uuid(_) => ValueType::Uuid,
            Value::Timestamp(_) => ValueType::Timestamp,
            Value::Json(_) => ValueType::Json,
            Value::Null => ValueType::Null,
        }
    }
    
    /// Serialize the value to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Value::Integer(v) => v.to_be_bytes().to_vec(),
            Value::BigInt(v) => v.to_be_bytes().to_vec(),
            Value::Float(v) => v.to_be_bytes().to_vec(),
            Value::Text(v) => v.as_bytes().to_vec(),
            Value::Binary(v) => v.clone(),
            Value::Boolean(v) => vec![if *v { 1 } else { 0 }],
            Value::Uuid(v) => v.as_bytes().to_vec(),
            Value::Timestamp(v) => v.to_be_bytes().to_vec(),
            Value::Json(v) => v.as_bytes().to_vec(),
            Value::Null => vec![],
        }
    }
}

/// A row in a database table
#[derive(Clone, Serialize, Deserialize)]
pub struct Row {
    /// Row identifier (primary key or internal ID)
    pub id: String,
    
    /// Table name this row belongs to
    pub table_name: String,
    
    /// Column values
    pub values: HashMap<String, Value>,
    
    /// Hash of the row
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<[u8; 32]>,
}

impl Debug for Row {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "Row {{ id: {}, table: {}, values: {:?} }}",
            self.id, self.table_name, self.values
        )
    }
}

impl Row {
    /// Create a new row
    pub fn new(id: String, table_name: String, values: HashMap<String, Value>) -> Self {
        let mut row = Row {
            id,
            table_name,
            values,
            hash: None,
        };
        
        // Calculate the hash
        row.hash = Some(row.calculate_hash());
        
        row
    }
    
    /// Calculate the hash of the row with domain separation
    pub fn calculate_hash(&self) -> [u8; 32] {
        // Serialize the row ID and table name
        let id_bytes = self.id.as_bytes();
        let table_bytes = self.table_name.as_bytes();
        
        // Collect all column names and values
        let mut column_values: Vec<(Vec<u8>, Vec<u8>)> = self
            .values
            .iter()
            .map(|(column, value)| (column.as_bytes().to_vec(), value.to_bytes()))
            .collect();
        
        // Sort by column name for deterministic ordering
        column_values.sort_by(|(a, _), (b, _)| a.cmp(b));
        
        // Concatenate all column names and values
        let mut all_data = Vec::new();
        for (column, value) in column_values {
            all_data.extend_from_slice(&column);
            all_data.extend_from_slice(&value);
        }
        
        // Hash the row with domain separation
        crypto::secure_hash_multiple(
            domains::ROW,
            &[id_bytes, table_bytes, &all_data]
        )
    }
    
    /// Get a value by column name
    pub fn get(&self, column: &str) -> Option<&Value> {
        self.values.get(column)
    }
    
    /// Set a value for a column
    pub fn set(&mut self, column: String, value: Value) {
        self.values.insert(column, value);
        // Update the hash
        self.hash = Some(self.calculate_hash());
    }
    
    /// Get the hash of the row
    pub fn hash(&self) -> [u8; 32] {
        self.hash.unwrap_or_else(|| self.calculate_hash())
    }
    
    /// Verify the hash of the row
    pub fn verify_hash(&self) -> bool {
        match self.hash {
            Some(hash) => hash == self.calculate_hash(),
            None => true, // No hash to verify
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_row_hash() {
        // Create a row
        let mut values = HashMap::new();
        values.insert("name".to_string(), Value::Text("John Doe".to_string()));
        values.insert("age".to_string(), Value::Integer(30));
        values.insert("active".to_string(), Value::Boolean(true));
        
        let row = Row::new("1".to_string(), "users".to_string(), values);
        
        // Verify the hash
        assert!(row.verify_hash());
        
        // Create a clone and modify it
        let mut row2 = row.clone();
        row2.set("age".to_string(), Value::Integer(31));
        
        // The hash should change
        assert_ne!(row.hash(), row2.hash());
        
        // Both rows should still have valid hashes
        assert!(row.verify_hash());
        assert!(row2.verify_hash());
    }
    
    #[test]
    fn test_row_ordering() {
        // Create two rows with the same values but different order
        let mut values1 = HashMap::new();
        values1.insert("name".to_string(), Value::Text("John Doe".to_string()));
        values1.insert("age".to_string(), Value::Integer(30));
        
        let mut values2 = HashMap::new();
        values2.insert("age".to_string(), Value::Integer(30));
        values2.insert("name".to_string(), Value::Text("John Doe".to_string()));
        
        let row1 = Row::new("1".to_string(), "users".to_string(), values1);
        let row2 = Row::new("1".to_string(), "users".to_string(), values2);
        
        // The hashes should be the same (column ordering shouldn't matter)
        assert_eq!(row1.hash(), row2.hash());
    }
    
    #[test]
    fn test_value_serialization() {
        // Test various value types
        let values = vec![
            Value::Integer(42),
            Value::BigInt(9223372036854775807),
            Value::Float(3.14159),
            Value::Text("Hello, world!".to_string()),
            Value::Binary(vec![1, 2, 3, 4, 5]),
            Value::Boolean(true),
            Value::Uuid(Uuid::new_v4()),
            Value::Timestamp(1609459200000), // 2021-01-01 00:00:00 UTC
            Value::Json(r#"{"key":"value"}"#.to_string()),
            Value::Null,
        ];
        
        for value in values {
            // Serialize and verify
            let bytes = value.to_bytes();
            
            // Make sure non-null values produce some bytes
            if !matches!(value, Value::Null) {
                assert!(!bytes.is_empty());
            }
            
            // Value type should match
            assert_eq!(value.value_type(), match value {
                Value::Integer(_) => ValueType::Integer,
                Value::BigInt(_) => ValueType::BigInt,
                Value::Float(_) => ValueType::Float,
                Value::Text(_) => ValueType::Text,
                Value::Binary(_) => ValueType::Binary,
                Value::Boolean(_) => ValueType::Boolean,
                Value::Uuid(_) => ValueType::Uuid,
                Value::Timestamp(_) => ValueType::Timestamp,
                Value::Json(_) => ValueType::Json,
                Value::Null => ValueType::Null,
            });
        }
    }
} 