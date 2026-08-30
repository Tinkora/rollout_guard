use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use rollout_guard::{scan_reader, Limits, Report};
use serde_json::json;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Explicit JSONL file or directory. Directories include only immediate *.jsonl files.
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_line_bytes: usize,
    #[arg(long, default_value_t = 0.50)]
    max_embedded_ratio: f64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    if !(0.0..=1.0).contains(&cli.max_embedded_ratio) {
        bail!("--max-embedded-ratio must be between 0 and 1");
    }
    let limits = Limits {
        max_line_bytes: cli.max_line_bytes,
        max_embedded_ratio: cli.max_embedded_ratio,
        ..Limits::default()
    };
    let paths = explicit_jsonl_paths(&cli.input)?;
    let mut reports = Vec::new();
    for path in paths {
        let file =
            File::open(&path).with_context(|| format!("cannot open {}", safe_name(&path)))?;
        reports.push(scan_reader(
            BufReader::new(file),
            &safe_name(&path),
            &limits,
        )?);
    }
    render(&reports, cli.format, std::io::stdout().lock())?;
    if reports.iter().any(|r| !r.findings.is_empty()) {
        std::process::exit(1);
    }
    Ok(())
}

fn explicit_jsonl_paths(input: &Path) -> Result<Vec<PathBuf>> {
    let input_metadata = fs::symlink_metadata(input)?;
    if input_metadata.file_type().is_symlink() {
        bail!("explicit symbolic-link inputs are not followed");
    }
    if input.is_file() {
        return Ok(vec![input.to_owned()]);
    }
    if !input.is_dir() {
        bail!("input must be an explicit file or directory");
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(input)? {
        let entry = entry.context("cannot read directory entry")?;
        let file_type = entry
            .file_type()
            .context("cannot inspect directory entry")?;
        let path = entry.path();
        if file_type.is_symlink() {
            bail!("directory contains a symbolic link: {}", safe_name(&path));
        }
        if file_type.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        bail!("directory contains no immediate .jsonl files");
    }
    Ok(paths)
}

fn safe_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("input")
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '/' | '\\') {
                '_'
            } else {
                character
            }
        })
        .collect()
}

fn render<W: Write>(reports: &[Report], format: Format, mut out: W) -> Result<()> {
    match format {
        Format::Json => serde_json::to_writer_pretty(&mut out, reports)?,
        Format::Text => {
            for r in reports {
                writeln!(
                    out,
                    "{}: {} bytes, {} lines, {} finding(s)",
                    r.source,
                    r.total_bytes,
                    r.line_count,
                    r.findings.len()
                )?;
            }
        }
        Format::Sarif => {
            let results: Vec<_> = reports.iter().flat_map(|r| r.findings.iter().map(|f| json!({
                "ruleId": f.rule_id, "level": "warning", "message": {"text": format!("{} occurrence(s)", f.count)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.source}}}]
            }))).collect();
            serde_json::to_writer_pretty(
                &mut out,
                &json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"rollout_guard","informationUri":"https://github.com/Tinkora/rollout_guard"}},"results":results}]}),
            )?;
        }
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_control_characters_in_source_names() {
        assert_eq!(safe_name(Path::new("bad\nname.jsonl")), "bad_name.jsonl");
    }

    #[cfg(unix)]
    #[test]
    fn directory_input_rejects_symlink_entries() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.jsonl");
        std::fs::write(&target, "{}\n").unwrap();
        symlink(&target, temp.path().join("link.jsonl")).unwrap();
        let error = explicit_jsonl_paths(temp.path()).unwrap_err();
        assert!(error.to_string().contains("symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn explicitly_named_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.jsonl");
        let link = temp.path().join("link.jsonl");
        std::fs::write(&target, "{}\n").unwrap();
        symlink(&target, &link).unwrap();
        let error = explicit_jsonl_paths(&link).unwrap_err();
        assert!(error.to_string().contains("symbolic-link inputs"));
    }
}
