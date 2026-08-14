# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-08-14

### Added
- **AI Content Remediator script** (`ai_content_remediator.py`) for automatically fixing common AI-generated content issues:
  - Remove HTML/XML comment blocks with `--remove-comments` flag
  - Normalize markdown spacing between elements (headings, paragraphs, lists, etc.)
  - Detect token repetition patterns for manual review
  - Detect prompt leakage patterns for manual review
  - Preserve internal notes sections marked with `## Internal notes`
- **Test files** for remediator validation:
  - `test_files/remediator_html_comments.md`
  - `test_files/remediator_spacing.md`
  - `test_files/remediator_token_repetition.md`
  - `test_files/remediator_internal_notes.md`

---

## [1.1.0] - 2026-08-14

### Added
- **Advanced AI watermark detection** based on statistical, structural, semantic, and Unicode patterns
- **Statistical analysis**: Sentence length variance, Type-Token Ratio (TTR), Moving-Average TTR (MATTR)
- **Structural analysis**: Markdown heading hierarchy consistency, list marker uniformity, code block language tagging, markdown spacing patterns
- **Unicode analysis**: Normalization form detection (NFC vs NFD), mathematical alphabetic characters, bidirectional override detection, tag characters
- **AI artifact detection**: Prompt leakage patterns, token repetition, EOS token patterns
- **POS tag n-gram analysis** (requires spaCy): Detects unusual part-of-speech sequences common in AI-generated text
- **Embedding clustering** (requires sentence-transformers): Detects tight semantic clustering typical of AI-generated content
- **Semantic drift analysis** (requires sentence-transformers): Measures topic consistency vs human writing
- `--advanced` flag to enable NLP-based checks (spaCy, sentence-transformers)
- `--no-statistical` flag to disable statistical/structural checks

### Changed
- Updated README.md to reference standalone `ai_watermark_scanner.py` script instead of inline code
- Removed embedded Python script from README.md Technical Implementation section
- Updated all script references from `scanner.py` to `ai_watermark_scanner.py`

### Documentation
- Added comprehensive documentation in `@docs/advanced-ai-watermark-detection.md` covering:
  - 15+ detection techniques across statistical, semantic, structural, and Unicode categories
  - Implementation examples with code snippets
  - Priority recommendations for different use cases
  - Threshold tuning guidelines
  - False positive mitigation strategies
  - Integration patterns with existing scanner

---

## [1.0.0] - 2026-08-14

### Added
- Comprehensive Python script `ai_watermark_scanner.py` for AI watermark detection
- Context-aware homoglyph detection to reduce false positives
- Binary file support for PNG/JPG C2PA metadata in JUMBF format
- Specific C2PA structural marker detection (namespaces, manifests, signatures)
- File type auto-detection using magic numbers
- JSON output format support with `--json` flag
- Verbose mode for detailed findings with `-v` flag
- Proper exit codes (0 = clean, 1 = watermarks found)

### Fixed
- **Critical**: Homoglyph detection no longer flags legitimate foreign language content (Cyrillic, Greek) as watermarks
- **Critical**: C2PA detection now uses specific structural markers instead of broad keywords like `<metadata` and `provenance`
- **Critical**: Binary image files (PNG/JPG) are now properly handled - C2PA metadata detection uses binary-aware JUMBF scanning
- **Critical**: Added detection for C2PA namespace declarations (`xmlns:c2pa="http://c2pa.org/"`) and structured manifest elements

### Changed
- Improved homoglyph detection algorithm with context analysis (Latin alphanumeric vs homoglyph ratios)
- Enhanced C2PA detection with regex patterns for specific structural elements
- Better file handling with proper binary/text mode selection

---

## [0.1.0] - 2026-08-14

### Added
- Initial README.md with comprehensive AI watermark detection guide
- EU AI Act Article 50(2) compliance methodology
- Detection methods for zero-width characters, C2PA metadata, homoglyph substitution
- Shell commands for quick watermark checking
- exiftool integration for image metadata analysis
- Step-by-step verification procedures
- Mitigation strategies for watermark removal and preservation

### Known Issues
- Homoglyph detection produced massive false positives for legitimate foreign language content
- C2PA indicators (`<metadata`, `provenance`) were too broad, causing false positives in legitimate SVG files
- Binary image files (PNG/JPG) were not properly handled for C2PA detection
- Missing structural C2PA markers (namespaces, manifests)

---

## Technical Details of Fixes

### Homoglyph Detection False Positives

**Problem**: Original script flagged every Cyrillic or Greek character as a watermark.

**Solution**: Implemented context-aware detection that distinguishes:
- **Watermark usage**: Homoglyphs mixed with Latin alphanumeric characters (e.g., `Clаude` with Cyrillic 'а')
- **Legitimate usage**: Homoglyphs in foreign language blocks (e.g., `Добро пожаловать`)

Algorithm:
- Analyzes surrounding 100 characters for each homoglyph
- Counts Latin alphanumeric vs homoglyph character ratios
- Only flags if homoglyph ratio < 30% and adjacent to Latin alphanumeric characters
- Requires nearby Latin words (3+ alphanumeric characters)

**Result**: New `suspicious_homoglyphs` field contains only potential watermarks, while `homoglyphs` contains all found for reference.

### C2PA Detection Too Broad

**Problem**: Broad keywords like `<metadata` and `provenance` caused false positives in legitimate SVG files.

**Solution**: Replaced with specific C2PA structural markers:
- Namespace URLs: `xmlns:c2pa="http://c2pa.org/"`, `xmlns:c2pa="https://c2pa.org/"`
- C2PA elements: `c2pa:manifest`, `c2pa:assertion`, `c2pa:signature`, `c2pa:claim`
- Regex patterns for structured manifest detection
- C2PA attributes: `c2pa:hash`, `c2pa:signature`

**Result**: C2PA detection now uses `c2pa_structural` field for specific markers.

### Binary Image Support

**Problem**: PNG/JPG files store C2PA as binary JUMBF, not UTF-8 text.

**Solution**: Implemented binary-aware detection:
- File type detection via magic numbers (PNG: `\x89PNG\r\n\x1a\n`, JPEG: `\xFF\xD8\xFF`)
- JUMBF magic number detection: `b'jumbf'`
- C2PA brand identifier: `b'c2pa'`
- PNG custom chunk scanning for C2PA-related types

**Result**: New fields `binary_c2pa_detected`, `jumbf_found`, `c2pa_brand_found`.

### Structural C2PA Markers

**Problem**: Original script missed namespace declarations and structured elements.

**Solution**: Added detection for:
- XML namespace declarations with C2PA URLs
- `c2pa:` prefixed elements
- `<manifest>` with C2PA namespace attributes
- Hash and signature elements
