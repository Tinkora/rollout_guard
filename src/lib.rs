use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::BufRead;

const MAX_DATA_URL_ENCODED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_line_bytes: usize,
    pub max_embedded_ratio: f64,
    pub max_duplicate_records: u64,
    pub max_malformed_lines: u64,
    pub max_tracked_hashes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 4 * 1024 * 1024,
            max_embedded_ratio: 0.50,
            max_duplicate_records: 0,
            max_malformed_lines: 0,
            max_tracked_hashes: 250_000,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub level: &'static str,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub source: String,
    pub total_bytes: u64,
    pub line_count: u64,
    pub max_line_bytes: u64,
    pub malformed_lines: u64,
    pub oversized_lines: u64,
    pub embedded_data_urls: u64,
    pub embedded_base64_bytes: u64,
    pub embedded_ratio: f64,
    pub skipped_large_data_urls: u64,
    pub duplicate_records: u64,
    pub duplicate_content_records: u64,
    pub repeated_instruction_records: u64,
    pub hash_tracking_saturated: bool,
    pub findings: Vec<Finding>,
}

pub fn scan_reader<R: BufRead>(mut reader: R, source: &str, limits: &Limits) -> Result<Report> {
    let mut report = Report {
        source: source.to_owned(),
        total_bytes: 0,
        line_count: 0,
        max_line_bytes: 0,
        malformed_lines: 0,
        oversized_lines: 0,
        embedded_data_urls: 0,
        embedded_base64_bytes: 0,
        embedded_ratio: 0.0,
        skipped_large_data_urls: 0,
        duplicate_records: 0,
        duplicate_content_records: 0,
        repeated_instruction_records: 0,
        hash_tracking_saturated: false,
        findings: Vec::new(),
    };
    let mut line = Vec::new();
    let mut record_hashes = HashSet::new();
    let mut content_hashes = HashSet::new();
    let mut instruction_hashes = HashSet::new();

    loop {
        line.clear();
        let (bytes, ended, oversized) =
            read_bounded_line(&mut reader, &mut line, limits.max_line_bytes)?;
        if bytes == 0 && !ended {
            break;
        }
        report.total_bytes += bytes as u64;
        report.line_count += 1;
        let logical_len = bytes.saturating_sub(usize::from(ended));
        report.max_line_bytes = report.max_line_bytes.max(logical_len as u64);
        if oversized {
            report.oversized_lines += 1;
            continue;
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(_) => {
                report.malformed_lines += 1;
                continue;
            }
        };
        track_hash(
            hash_bytes(&line),
            &mut record_hashes,
            limits,
            &mut report.hash_tracking_saturated,
            &mut report.duplicate_records,
        );
        if let Some(content) = value.get("content") {
            let hash = hash_value(content)?;
            track_hash(
                hash,
                &mut content_hashes,
                limits,
                &mut report.hash_tracking_saturated,
                &mut report.duplicate_content_records,
            );
        }
        for instruction in explicit_instructions(&value) {
            let hash = hash_bytes(instruction.as_bytes());
            track_hash(
                hash,
                &mut instruction_hashes,
                limits,
                &mut report.hash_tracking_saturated,
                &mut report.repeated_instruction_records,
            );
        }
        inspect_data_urls(&value, &mut report);
    }
    if report.total_bytes > 0 {
        report.embedded_ratio = report.embedded_base64_bytes as f64 / report.total_bytes as f64;
    }
    add_findings(&mut report, limits);
    Ok(report)
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    stored: &mut Vec<u8>,
    cap: usize,
) -> Result<(usize, bool, bool)> {
    let mut total = 0usize;
    let mut ended = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if stored.len() < cap + 1 {
            let retain = take.min(cap + 1 - stored.len());
            stored.extend_from_slice(&available[..retain]);
        }
        total = total.saturating_add(take);
        ended = available[take - 1] == b'\n';
        reader.consume(take);
        if ended {
            break;
        }
    }
    Ok((total, ended, total.saturating_sub(usize::from(ended)) > cap))
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn track_hash(
    hash: [u8; 32],
    hashes: &mut HashSet<[u8; 32]>,
    limits: &Limits,
    saturated: &mut bool,
    duplicates: &mut u64,
) {
    if hashes.contains(&hash) {
        *duplicates += 1;
    } else if hashes.len() < limits.max_tracked_hashes {
        hashes.insert(hash);
    } else {
        *saturated = true;
    }
}

fn hash_value(value: &Value) -> Result<[u8; 32]> {
    Ok(hash_bytes(
        &serde_json::to_vec(value).context("serialize JSON value")?,
    ))
}

fn explicit_instructions(value: &Value) -> Vec<&str> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    ["instruction", "system_instruction", "prompt"]
        .iter()
        .filter_map(|key| object.get(*key)?.as_str())
        .collect()
}

fn inspect_data_urls(value: &Value, report: &mut Report) {
    match value {
        Value::String(text) => {
            let Some((metadata, encoded)) =
                text.strip_prefix("data:").and_then(|s| s.split_once(','))
            else {
                return;
            };
            if !metadata.to_ascii_lowercase().ends_with(";base64") {
                return;
            }
            if encoded.len() > MAX_DATA_URL_ENCODED_BYTES {
                report.skipped_large_data_urls += 1;
                return;
            }
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                report.embedded_data_urls += 1;
                report.embedded_base64_bytes += decoded.len() as u64;
            }
        }
        Value::Array(items) => items.iter().for_each(|v| inspect_data_urls(v, report)),
        Value::Object(object) => object.values().for_each(|v| inspect_data_urls(v, report)),
        _ => {}
    }
}

fn add_findings(report: &mut Report, limits: &Limits) {
    let rules = [
        (
            "RG001_MALFORMED_JSONL",
            report.malformed_lines > limits.max_malformed_lines,
            report.malformed_lines,
        ),
        (
            "RG002_OVERSIZED_LINE",
            report.oversized_lines > 0,
            report.oversized_lines,
        ),
        (
            "RG003_EMBEDDED_DATA_RATIO",
            report.embedded_ratio > limits.max_embedded_ratio,
            report.embedded_data_urls,
        ),
        (
            "RG004_DUPLICATE_RECORD",
            report.duplicate_records > limits.max_duplicate_records,
            report.duplicate_records,
        ),
        (
            "RG005_DUPLICATE_CONTENT",
            report.duplicate_content_records > limits.max_duplicate_records,
            report.duplicate_content_records,
        ),
        (
            "RG006_REPEATED_INSTRUCTION",
            report.repeated_instruction_records > limits.max_duplicate_records,
            report.repeated_instruction_records,
        ),
        (
            "RG007_UNINSPECTED_DATA_URL",
            report.skipped_large_data_urls > 0,
            report.skipped_large_data_urls,
        ),
        (
            "RG008_HASH_TRACKING_SATURATED",
            report.hash_tracking_saturated,
            1,
        ),
    ];
    report
        .findings
        .extend(
            rules
                .into_iter()
                .filter(|(_, hit, _)| *hit)
                .map(|(rule_id, _, count)| Finding {
                    rule_id,
                    level: "warning",
                    count,
                }),
        );
}
