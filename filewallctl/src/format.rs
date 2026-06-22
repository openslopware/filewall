//! Output-format selection. A global, position-independent flag (`--json`,
//! `--yaml`, or `--table`) is extracted from argv before subcommand dispatch.
//! Default is `Table` everywhere (no TTY auto-switching); if more than one flag
//! is given, the last one wins.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    Yaml,
}

/// Split `args` into the chosen [`Format`] and the remaining (non-format) args.
/// Order of the remaining args is preserved.
pub fn parse_format(args: &[String]) -> (Format, Vec<String>) {
    let mut fmt = Format::Table;
    let mut rest = Vec::with_capacity(args.len());
    for a in args {
        match a.as_str() {
            "--json" => fmt = Format::Json,
            "--yaml" => fmt = Format::Yaml,
            "--table" => fmt = Format::Table,
            _ => rest.push(a.clone()),
        }
    }
    (fmt, rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_is_table() {
        let (fmt, rest) = parse_format(&v(&["dump"]));
        assert_eq!(fmt, Format::Table);
        assert_eq!(rest, v(&["dump"]));
    }

    #[test]
    fn json_flag_anywhere_is_extracted() {
        let (fmt, rest) = parse_format(&v(&["list", "--json", "/path"]));
        assert_eq!(fmt, Format::Json);
        assert_eq!(rest, v(&["list", "/path"]));
    }

    #[test]
    fn last_flag_wins() {
        let (fmt, _) = parse_format(&v(&["--json", "dump", "--yaml"]));
        assert_eq!(fmt, Format::Yaml);
    }

    #[test]
    fn yaml_flag() {
        let (fmt, rest) = parse_format(&v(&["status", "--yaml"]));
        assert_eq!(fmt, Format::Yaml);
        assert_eq!(rest, v(&["status"]));
    }
}
