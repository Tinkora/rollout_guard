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
    if input.is_file() {
        return Ok(vec![input.to_owned()]);
    }
    if !input.is_dir() {
        bail!("input must be an explicit file or directory");
    }
    let mut paths: Vec<_> = fs::read_dir(input)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"))
        })
        .collect();
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
        .to_owned()
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
