//! String utility functions
//!
//! This module provides various string manipulation and utility functions.

/// String utility functions
#[derive(Debug)]
pub struct StringUtils;

impl StringUtils {
    /// Truncate a string to a maximum length with ellipsis
    pub fn truncate(s: &str, max_length: usize) -> String {
        if s.len() <= max_length {
            s.to_string()
        } else {
            let mut result = s[..max_length].to_string();
            result.push_str("...");
            result
        }
    }
    
    /// Ensure a string starts with a specific prefix
    pub fn ensure_starts_with(s: &str, prefix: &str) -> String {
        if s.starts_with(prefix) {
            s.to_string()
        } else {
            format!("{}{}", prefix, s)
        }
    }
    
    /// Ensure a string ends with a specific suffix
    pub fn ensure_ends_with(s: &str, suffix: &str) -> String {
        if s.ends_with(suffix) {
            s.to_string()
        } else {
            format!("{}{}", s, suffix)
        }
    }
    
    /// Remove all whitespace from a string
    pub fn remove_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }
    
    /// Convert a camelCase string to snake_case
    pub fn camel_to_snake(s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c.is_uppercase() {
                if !result.is_empty() {
                    result.push('_');
                }
                result.push(c.to_lowercase().next().unwrap());
            } else {
                result.push(c);
            }
        }
        
        result
    }
    
    /// Convert a snake_case string to camelCase
    pub fn snake_to_camel(s: &str) -> String {
        let mut result = String::new();
        let mut capitalize_next = false;
        
        for c in s.chars() {
            if c == '_' {
                capitalize_next = true;
            } else if capitalize_next {
                result.push(c.to_uppercase().next().unwrap());
                capitalize_next = false;
            } else {
                result.push(c);
            }
        }
        
        result
    }
    
    /// Convert a snake_case or camelCase string to PascalCase
    pub fn to_pascal_case(s: &str) -> String {
        let camel = if s.contains('_') {
            Self::snake_to_camel(s)
        } else {
            s.to_string()
        };
        
        if camel.is_empty() {
            return camel;
        }
        
        let mut result = String::new();
        let mut chars = camel.chars();
        
        if let Some(first) = chars.next() {
            result.push(first.to_uppercase().next().unwrap());
            result.extend(chars);
        }
        
        result
    }
    
    /// Pluralize a word based on count
    pub fn pluralize(word: &str, count: usize) -> String {
        if count == 1 {
            word.to_string()
        } else {
            // This is very simplified - real pluralization is much more complex
            match word {
                // Special cases
                "person" => "people".to_string(),
                "child" => "children".to_string(),
                "ox" => "oxen".to_string(),
                "tooth" => "teeth".to_string(),
                "foot" => "feet".to_string(),
                "mouse" => "mice".to_string(),
                // Regular rules
                w if w.ends_with('s') || w.ends_with('x') || w.ends_with('z') || w.ends_with("ch") || w.ends_with("sh") => format!("{}es", w),
                w if w.ends_with('y') && !['a', 'e', 'i', 'o', 'u'].contains(&w.chars().rev().nth(1).unwrap_or('a')) => {
                    let mut s = w.to_string();
                    s.pop();
                    format!("{}ies", s)
                }
                w => format!("{}s", w),
            }
        }
    }
    
    /// Check if a string is a valid identifier
    pub fn is_valid_identifier(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        
        let mut chars = s.chars();
        
        // First character must be a letter or underscore
        match chars.next() {
            Some(c) if c.is_alphabetic() || c == '_' => {}
            _ => return false,
        }
        
        // Remaining characters must be alphanumeric or underscore
        chars.all(|c| c.is_alphanumeric() || c == '_')
    }
    
    /// Format a byte size with the appropriate unit (B, KB, MB, GB, etc.)
    pub fn format_bytes(size: u64) -> String {
        const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
        
        if size == 0 {
            return "0 B".to_string();
        }
        
        if size < 1024 {
            return format!("{} B", size);
        }
        
        let digits = (size as f64).log10() as usize;
        let unit = std::cmp::min(digits / 3, UNITS.len() - 1);
        
        let size_in_unit = size as f64 / 1024_f64.powi(unit as i32);
        
        format!("{:.2} {}", size_in_unit, UNITS[unit])
    }
    
    /// Format a duration in milliseconds to a human-readable string
    pub fn format_duration(millis: u64) -> String {
        if millis < 1000 {
            return format!("{}ms", millis);
        }
        
        let seconds = millis / 1000;
        if seconds < 60 {
            return format!("{}.{:03}s", seconds, millis % 1000);
        }
        
        let minutes = seconds / 60;
        let remaining_seconds = seconds % 60;
        if minutes < 60 {
            return format!("{}m {}s", minutes, remaining_seconds);
        }
        
        let hours = minutes / 60;
        let remaining_minutes = minutes % 60;
        if hours < 24 {
            return format!("{}h {}m {}s", hours, remaining_minutes, remaining_seconds);
        }
        
        let days = hours / 24;
        let remaining_hours = hours % 24;
        format!("{}d {}h {}m {}s", days, remaining_hours, remaining_minutes, remaining_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_truncate() {
        assert_eq!(StringUtils::truncate("Hello", 10), "Hello");
        assert_eq!(StringUtils::truncate("Hello, world!", 5), "Hello...");
        assert_eq!(StringUtils::truncate("", 5), "");
    }
    
    #[test]
    fn test_ensure_starts_with() {
        assert_eq!(StringUtils::ensure_starts_with("example", "https://"), "https://example");
        assert_eq!(StringUtils::ensure_starts_with("https://example", "https://"), "https://example");
        assert_eq!(StringUtils::ensure_starts_with("", "prefix"), "prefix");
    }
    
    #[test]
    fn test_ensure_ends_with() {
        assert_eq!(StringUtils::ensure_ends_with("example", "/"), "example/");
        assert_eq!(StringUtils::ensure_ends_with("example/", "/"), "example/");
        assert_eq!(StringUtils::ensure_ends_with("", "suffix"), "suffix");
    }
    
    #[test]
    fn test_remove_whitespace() {
        assert_eq!(StringUtils::remove_whitespace("Hello world"), "Helloworld");
        assert_eq!(StringUtils::remove_whitespace(" a b c "), "abc");
        assert_eq!(StringUtils::remove_whitespace(""), "");
    }
    
    #[test]
    fn test_camel_to_snake() {
        assert_eq!(StringUtils::camel_to_snake("camelCase"), "camel_case");
        assert_eq!(StringUtils::camel_to_snake("CamelCase"), "camel_case");
        assert_eq!(StringUtils::camel_to_snake("simpleword"), "simpleword");
        assert_eq!(StringUtils::camel_to_snake("ABC"), "a_b_c");
        assert_eq!(StringUtils::camel_to_snake("ABCWord"), "a_b_c_word");
    }
    
    #[test]
    fn test_snake_to_camel() {
        assert_eq!(StringUtils::snake_to_camel("snake_case"), "snakeCase");
        assert_eq!(StringUtils::snake_to_camel("simple_word"), "simpleWord");
        assert_eq!(StringUtils::snake_to_camel("simpleword"), "simpleword");
        assert_eq!(StringUtils::snake_to_camel("a_b_c"), "aBC");
    }
    
    #[test]
    fn test_to_pascal_case() {
        assert_eq!(StringUtils::to_pascal_case("snake_case"), "SnakeCase");
        assert_eq!(StringUtils::to_pascal_case("camelCase"), "CamelCase");
        assert_eq!(StringUtils::to_pascal_case("simple"), "Simple");
        assert_eq!(StringUtils::to_pascal_case(""), "");
    }
    
    #[test]
    fn test_pluralize() {
        assert_eq!(StringUtils::pluralize("apple", 1), "apple");
        assert_eq!(StringUtils::pluralize("apple", 2), "apples");
        assert_eq!(StringUtils::pluralize("person", 1), "person");
        assert_eq!(StringUtils::pluralize("person", 2), "people");
        assert_eq!(StringUtils::pluralize("box", 2), "boxes");
        assert_eq!(StringUtils::pluralize("cherry", 2), "cherries");
    }
    
    #[test]
    fn test_is_valid_identifier() {
        assert!(StringUtils::is_valid_identifier("valid_identifier"));
        assert!(StringUtils::is_valid_identifier("_valid"));
        assert!(StringUtils::is_valid_identifier("valid123"));
        assert!(!StringUtils::is_valid_identifier("123invalid"));
        assert!(!StringUtils::is_valid_identifier("invalid-identifier"));
        assert!(!StringUtils::is_valid_identifier(""));
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(StringUtils::format_bytes(0), "0 B");
        assert_eq!(StringUtils::format_bytes(1023), "1023 B");
        assert_eq!(StringUtils::format_bytes(1024), "1.00 KB");
        assert_eq!(StringUtils::format_bytes(1536), "1.50 KB");
        assert_eq!(StringUtils::format_bytes(1048576), "1.00 MB");
        assert_eq!(StringUtils::format_bytes(1073741824), "1.00 GB");
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(StringUtils::format_duration(500), "500ms");
        assert_eq!(StringUtils::format_duration(1500), "1.500s");
        assert_eq!(StringUtils::format_duration(65000), "1m 5s");
        assert_eq!(StringUtils::format_duration(3665000), "1h 1m 5s");
        assert_eq!(StringUtils::format_duration(90061000), "1d 1h 1m 1s");
    }
} 