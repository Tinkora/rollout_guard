# Product specification

## Problem

Agent evaluation and rollout exports can silently become unsafe to move or review because records are malformed, single lines defeat normal tools, binary data is embedded, or retries duplicate payloads. Existing generic JSON tools commonly load a complete document and do not express these rollout-oriented aggregate risks.

## MVP contract

`rollout_guard` performs read-only, offline, streaming analysis of explicitly selected JSONL files. It emits text, JSON, or SARIF summaries without input values or absolute paths. Its stable rule identifiers are documented in the README. Thresholds are policy, not claims that an artifact is malicious.

## Non-goals

No home-directory discovery, recursive scan, symlink traversal, upload, deletion, mutation, redaction, conversion, replay, semantic prompt classification, arbitrary base64 guessing, or support claim for every agent framework. Both explicitly named symlinks and symlink entries in selected directories are rejected.

## Resource bounds

The scanner does not buffer a whole file. A line retains at most the configured line cap plus one byte. Explicit data URLs above 8 MiB encoded length are counted as uninspected rather than decoded. Duplicate tracking retains at most 250,000 hashes per category and reports saturation rather than silently claiming complete detection.
