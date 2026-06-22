//! Output rendering. `emit` serializes any `Serialize` value as JSON or YAML;
//! `render_table` lays out aligned columns for the human-default table view.

use crate::format::Format;
use serde::Serialize;

/// Serialize `value` as JSON or YAML. Not used for `Format::Table` (callers
/// render their own table layout). Returns the serialized string.
pub fn emit<T: Serialize>(value: &T, format: Format) -> Result<String, String> {
    match format {
        Format::Json => serde_json::to_string_pretty(value).map_err(|e| e.to_string()),
        Format::Yaml => serde_norway::to_string(value).map_err(|e| e.to_string()),
        Format::Table => Err("emit() called with Format::Table".to_string()),
    }
}

/// Render rows as a left-aligned, space-padded table with a header row. Column
/// widths are the max cell width in each column. `headers.len()` defines the
/// column count; each row must have the same length.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .take(cols)
            .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = String::new();
    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    out.push_str(&fmt_row(&header_cells));
    out.push('\n');
    for row in rows {
        out.push_str(&fmt_row(row));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns_and_has_header() {
        let rows = vec![
            vec!["/a".to_string(), "dir".to_string()],
            vec!["/longer/path".to_string(), "file".to_string()],
        ];
        let out = render_table(&["PATH", "KIND"], &rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "PATH          KIND");
        assert_eq!(lines[1], "/a            dir");
        assert_eq!(lines[2], "/longer/path  file");
    }

    #[test]
    fn emit_json_is_pretty_and_parseable() {
        #[derive(serde::Serialize)]
        struct S {
            a: u32,
        }
        let s = emit(&S { a: 1 }, Format::Json).unwrap();
        assert!(s.contains("\"a\": 1"));
    }

    #[test]
    fn emit_yaml_renders_key() {
        #[derive(serde::Serialize)]
        struct S {
            a: u32,
        }
        let s = emit(&S { a: 1 }, Format::Yaml).unwrap();
        assert!(s.contains("a: 1"));
    }
}
