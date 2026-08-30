use rollout_guard::{scan_reader, Limits};
use std::io::Cursor;

#[test]
fn reports_malformed_duplicates_and_embedded_payloads_without_content() {
    let input = concat!(
        "{\"id\":1,\"content\":\"same\",\"instruction\":\"Do the work\",\"image\":\"data:text/plain;base64,SGVsbG8=\"}\n",
        "{\"id\":1,\"content\":\"same\",\"instruction\":\"Do the work\"}\n",
        "not json\n"
    );
    let report = scan_reader(Cursor::new(input), "fixture.jsonl", &Limits::default()).unwrap();
    assert_eq!(report.line_count, 3);
    assert_eq!(report.malformed_lines, 1);
    assert_eq!(report.duplicate_content_records, 1);
    assert_eq!(report.repeated_instruction_records, 1);
    assert_eq!(report.embedded_base64_bytes, 5);
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("Do the work"));
    assert!(!rendered.contains("SGVsbG8"));
}

#[test]
fn bounds_huge_lines_and_continues_to_the_next_record() {
    let input = format!("{{\"content\":\"{}\"}}\n{{\"ok\":true}}\n", "x".repeat(128));
    let limits = Limits {
        max_line_bytes: 32,
        ..Limits::default()
    };
    let report = scan_reader(Cursor::new(input.as_bytes()), "huge.jsonl", &limits).unwrap();
    assert_eq!(report.line_count, 2);
    assert_eq!(report.oversized_lines, 1);
    assert_eq!(report.malformed_lines, 0);
    assert!(report.max_line_bytes > 32);
}

#[test]
fn plain_base64_like_text_is_not_guessed_as_payload() {
    let input = "{\"note\":\"VGhpcyBpcyBqdXN0IHRleHQ=\"}\n";
    let report = scan_reader(Cursor::new(input), "plain.jsonl", &Limits::default()).unwrap();
    assert_eq!(report.embedded_base64_bytes, 0);
}

#[test]
fn bounds_duplicate_tracking_cardinality() {
    let input = "{\"content\":1}\n{\"content\":2}\n{\"content\":1}\n";
    let limits = Limits {
        max_tracked_hashes: 1,
        ..Limits::default()
    };
    let report = scan_reader(Cursor::new(input), "bounded.jsonl", &limits).unwrap();
    assert!(report.hash_tracking_saturated);
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "RG008_HASH_TRACKING_SATURATED"));
}
