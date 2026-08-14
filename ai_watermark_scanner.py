#!/usr/bin/env python3
"""
AI Watermark Detection Scanner - Improved Version

This script detects AI watermarks in files with reduced false positives.
It addresses critical limitations of the original implementation:

1. Homoglyph detection is now context-aware to avoid flagging legitimate
   foreign language content (Cyrillic, Greek, etc.) as watermarks.
   
2. C2PA detection uses specific structural markers (namespaces, manifests)
   instead of broad keywords that cause false positives.
   
3. Binary files (PNG, JPG) are handled properly - they're not decoded as text,
   and C2PA detection uses binary-aware approaches.
   
4. Added proper C2PA namespace and manifest hash detection.

Usage:
    python3 ai_watermark_scanner.py /path/to/scan
    python3 ai_watermark_scanner.py --binary-check file.png
"""

import os
import sys
import re
import struct
import statistics
import unicodedata
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter


# =============================================================================
# CONFIGURATION: Zero-width characters (unchanged from original)
# =============================================================================

ZERO_WIDTH_CHARS = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF']
VARIATION_SELECTORS = [chr(i) for i in range(0xFE00, 0xFE10)]


# =============================================================================
# IMPROVED: C2PA markers - specific structural patterns
# =============================================================================

# Specific C2PA namespace URLs and prefixes
C2PA_NAMESPACE_URLS = [
    'http://c2pa.org/',
    'https://c2pa.org/',
    'http://ns.c2pa.org/',
    'https://ns.c2pa.org/',
]

# Specific C2PA element and attribute patterns
C2PA_STRUCTURAL_INDICATORS = [
    # Namespace declarations
    r'xmlns\s*:\s*c2pa\s*=\s*["\']http[s]?://(ns\.)?c2pa\.org/["\']',
    r'xmlns\s*=\s*["\']http[s]?://(ns\.)?c2pa\.org/["\']',
    
    # C2PA prefixed elements
    r'c2pa:manifest',
    r'c2pa:assertion',
    r'c2pa:signature',
    r'c2pa:claim',
    r'c2pa:generator',
    r'c2pa:action',
    r'c2pa:relationship',
    
    # Structured manifest patterns
    r'<manifest[^>]*xmlns[^>]*c2pa',
    r'<c2pa:manifest',
    
    # C2PA-specific attributes
    r'c2pa\.hash',
    r'c2pa\.signature',
    r'c2pa:hash',
    r'c2pa:signature',
]

# Legacy broader indicators (kept for backwards compatibility but lower priority)
C2PA_LEGACY_INDICATORS = ['c2pa:', 'provenance', 'xmp:']

# JUMBF binary signature magic numbers (for PNG/JPG C2PA)
JUMBF_MAGIC = b'jumbf'
C2PA_BRAND = b'c2pa'


# =============================================================================
# IMPROVED: Homoglyph detection - context aware
# =============================================================================

# Homoglyph map remains the same for reference
HOMOGLYPH_MAP = {
    # Cyrillic homoglyphs
    '\u0430': 'a',  # а -> a
    '\u0431': 'b',  # б -> b
    '\u0432': 'v',  # в -> v
    '\u0433': 'g',  # г -> g
    '\u0434': 'd',  # д -> d
    '\u0435': 'e',  # е -> e
    '\u0436': 'zh', # ж -> zh
    '\u0437': 'z',  # з -> z
    '\u0438': 'i',  # и -> i
    '\u0439': 'i',  # й -> i
    '\u043A': 'k',  # к -> k
    '\u043B': 'l',  # л -> l
    '\u043C': 'm',  # м -> m
    '\u043D': 'n',  # н -> n
    '\u043E': 'o',  # о -> o
    '\u043F': 'p',  # п -> p
    '\u0440': 'r',  # р -> r
    '\u0441': 's',  # с -> s
    '\u0442': 't',  # т -> t
    '\u0443': 'u',  # у -> u
    '\u0444': 'f',  # ф -> f
    '\u0445': 'h',  # х -> h
    '\u0446': 'c',  # ц -> c
    '\u0447': 'ch', # ч -> ch
    '\u0448': 'sh', # ш -> sh
    '\u0449': 'sh', # щ -> sh
    '\u044A': '',   # ъ -> (hard sign)
    '\u044B': 'y',  # ы -> y
    '\u044C': '',   # ь -> (soft sign)
    '\u044D': 'e',  # э -> e
    '\u044E': 'yu', # ю -> yu
    '\u044F': 'ya', # я -> ya
    # Greek homoglyphs
    '\u03B1': 'a',  # α -> a
    '\u03B2': 'b',  # β -> b
    '\u03B3': 'g',  # γ -> g
    '\u03B4': 'd',  # δ -> d
    '\u03B5': 'e',  # ε -> e
    '\u03B6': 'z',  # ζ -> z
    '\u03B7': 'h',  # η -> h
    '\u03B8': 'th', # θ -> th
    '\u03B9': 'i',  # ι -> i
    '\u03BA': 'k',  # κ -> k
    '\u03BB': 'l',  # λ -> l
    '\u03BC': 'm',  # μ -> m
    '\u03BD': 'n',  # ν -> n
    '\u03BE': 'x',  # ξ -> x
    '\u03BF': 'o',  # ο -> o
    '\u03C0': 'p',  # π -> p
    '\u03C1': 'r',  # ρ -> r
    '\u03C2': 's',  # ς -> s
    '\u03C3': 's',  # σ -> s
    '\u03C4': 't',  # τ -> t
    '\u03C5': 'u',  # υ -> u
    '\u03C6': 'f',  # φ -> f
    '\u03C7': 'ch', # χ -> ch
    '\u03C8': 'ps', # ψ -> ps
    '\u03C9': 'w',  # ω -> w
}

# Unicode ranges for non-Latin scripts that have homoglyphs
HOMOGLYPH_SCRIPT_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek and Coptic
]

# Latin script ranges (for context detection)
# For watermark detection, we care about Latin ALPHANUMERIC characters
# Punctuation and whitespace alone shouldn't trigger false positives
LATIN_ALPHANUMERIC = [
    (0x0041, 0x005A),  # A-Z
    (0x0061, 0x007A),  # a-z
    (0x0030, 0x0039),  # Digits
]

LATIN_PUNCTUATION = [
    (0x0020, 0x002F),  # Basic punctuation
    (0x003A, 0x0040),  # More punctuation
    (0x005B, 0x0060),  # More punctuation
    (0x007B, 0x007E),  # More punctuation
]

# All Latin (including punctuation and whitespace)
LATIN_SCRIPT_RANGES = LATIN_ALPHANUMERIC + LATIN_PUNCTUATION

# Common Latin words/patterns that might appear near homoglyph watermarks
LATIN_CONTEXT_PATTERN = re.compile(
    r'[a-zA-Z0-9]{3,}'  # At least 3 Latin alphanumeric characters in context
)


def is_latin_char(char: str) -> bool:
    """Check if a character is in the Latin script range (including punctuation)."""
    code = ord(char)
    return any(start <= code <= end for start, end in LATIN_SCRIPT_RANGES)


def is_latin_alphanumeric(char: str) -> bool:
    """Check if a character is a Latin alphanumeric (letter or digit)."""
    code = ord(char)
    return any(start <= code <= end for start, end in LATIN_ALPHANUMERIC)


def is_homoglyph_char(char: str) -> bool:
    """Check if a character is in a homoglyph script range."""
    code = ord(char)
    return any(start <= code <= end for start, end in HOMOGLYPH_SCRIPT_RANGES)


def get_surrounding_context(content: str, position: int, radius: int = 50) -> str:
    """Get text surrounding a position for context analysis."""
    start = max(0, position - radius)
    end = min(len(content), position + radius + 1)
    return content[start:end]


def is_homoglyph_in_latin_context(content: str, position: int) -> bool:
    """
    Check if a homoglyph character appears in a context that suggests
    it might be used as a watermark (mixed with Latin text) rather than
    legitimate foreign language content.
    
    Returns True if the homoglyph appears to be in a watermark-like context.
    """
    context = get_surrounding_context(content, position, 100)
    
    # Count Latin ALPHANUMERIC vs non-Latin characters in context
    # We only care about alphanumeric Latin characters for watermark detection
    latin_alpha_count = sum(1 for c in context if is_latin_alphanumeric(c))
    homoglyph_count = sum(1 for c in context if is_homoglyph_char(c))
    # Also count whitespace and punctuation as "other"
    other_count = sum(1 for c in context if not is_homoglyph_char(c) and not is_latin_alphanumeric(c))
    total_chars = len(context)
    
    # If the context is mostly Latin alphanumeric with a few homoglyphs, it's likely a watermark
    # If it's mostly non-Latin, it's likely legitimate foreign text
    if total_chars == 0:
        return False
    
    # Only consider context with actual alphanumeric Latin characters
    if latin_alpha_count == 0:
        return False
    
    # Calculate ratio of homoglyphs to Latin alphanumeric
    # If homoglyphs are a small percentage of alphanumeric content, it's likely watermark
    total_meaningful = latin_alpha_count + homoglyph_count
    if total_meaningful == 0:
        return False
    
    homoglyph_ratio = homoglyph_count / total_meaningful
    
    # Watermark context: mostly Latin alphanumeric with a few homoglyphs mixed in
    # If <30% of meaningful characters are homoglyphs, and we have Latin words, it's watermark-like
    if homoglyph_ratio < 0.3:
        # Check if there are actual Latin words (3+ alphanumeric chars) nearby
        if LATIN_CONTEXT_PATTERN.search(context):
            # Check if the homoglyph is adjacent to Latin ALPHANUMERIC characters
            if (position > 0 and is_latin_alphanumeric(content[position-1])) or \
               (position < len(content)-1 and is_latin_alphanumeric(content[position+1])):
                return True
    
    return False


def check_binary_c2pa(filepath: str) -> Dict[str, Any]:
    """
    Check a binary file (PNG, JPG) for C2PA metadata in JUMBF format.
    
    Returns a dict with detection results.
    """
    results = {
        'binary_c2pa_detected': False,
        'jumbf_found': False,
        'c2pa_brand_found': False,
        'binary_error': None
    }
    
    try:
        with open(filepath, 'rb') as f:
            # Read enough bytes to scan for JUMBF signatures
            # JUMBF boxes can be anywhere, but typically near the end for PNG
            # For efficiency, we'll scan the first 1MB and last 1MB
            file_size = os.path.getsize(filepath)
            
            # Read chunks to search for JUMBF
            chunk_size = 1024 * 1024  # 1MB
            
            # Check first chunk
            f.seek(0)
            first_chunk = f.read(min(chunk_size, file_size))
            
            # Check last chunk
            if file_size > chunk_size:
                f.seek(max(0, file_size - chunk_size))
                last_chunk = f.read(chunk_size)
            else:
                last_chunk = b''
            
            all_data = first_chunk + last_chunk
            
            # Look for JUMBF magic number
            if JUMBF_MAGIC in all_data:
                results['jumbf_found'] = True
                # JUMBF found, now look for C2PA brand
                # In JUMBF, brands are 4-byte identifiers
                # Search for 'c2pa' brand
                if C2PA_BRAND in all_data:
                    results['c2pa_brand_found'] = True
                    results['binary_c2pa_detected'] = True
                    return results
                
                # Also search for case variations or with null terminators
                # Some implementations might use different formatting
                for i in range(len(all_data) - 4):
                    brand = all_data[i:i+4]
                    if brand.lower() == b'c2pa':
                        results['c2pa_brand_found'] = True
                        results['binary_c2pa_detected'] = True
                        return results
            
            # For PNG files, also check for specific C2PA-related chunks
            # PNG chunks are 4-byte type + data + 4-byte CRC
            # C2PA might be stored in a custom chunk like 'c2pa', 'C2PA', etc.
            if filepath.lower().endswith('.png'):
                # PNG signature
                png_sig = b'\x89PNG\r\n\x1a\n'
                if first_chunk.startswith(png_sig):
                    # Scan for chunk types
                    pos = 8  # After PNG signature
                    while pos < len(first_chunk) - 8:
                        chunk_type = first_chunk[pos:pos+4]
                        if chunk_type.lower() in [b'c2pa', b'prvn', b'meta']:
                            results['binary_c2pa_detected'] = True
                            return results
                        # Skip to next chunk (length is 4 bytes before type)
                        if pos >= 4:
                            chunk_length = struct.unpack('>I', first_chunk[pos-4:pos])[0]
                            pos += chunk_length + 12  # length + type + data + crc
                        else:
                            pos += 1
            
    except Exception as e:
        results['binary_error'] = str(e)
    
    return results


def get_file_type(filepath: str) -> str:
    """
    Determine file type based on extension and magic numbers.
    Returns 'text', 'svg', 'png', 'jpg', or 'binary'.
    """
    ext = filepath.lower()
    
    # Check by extension first
    if ext.endswith('.svg'):
        return 'svg'
    elif ext.endswith('.png'):
        return 'png'
    elif ext.endswith(('.jpg', '.jpeg')):
        return 'jpg'
    elif ext.endswith(('.txt', '.md', '.html', '.htm', '.json', '.xml', '.yaml', '.yml', '.css', '.js')):
        return 'text'
    
    # Check magic numbers for unknown extensions
    try:
        with open(filepath, 'rb') as f:
            header = f.read(32)
            
            # SVG
            if header.lstrip().startswith(b'<?xml') or header.lstrip().startswith(b'<svg'):
                return 'svg'
            
            # PNG
            if header.startswith(b'\x89PNG\r\n\x1a\n'):
                return 'png'
            
            # JPEG
            if header.startswith(b'\xFF\xD8\xFF'):
                return 'jpg'
            
            # UTF-8 BOM
            if header.startswith(b'\xEF\xBB\xBF'):
                return 'text'
            
            # Check if it looks like text (no null bytes in first 1KB)
            f.seek(0)
            sample = f.read(1024)
            if b'\x00' not in sample:
                return 'text'
            
            return 'binary'
    except Exception:
        return 'unknown'


# =============================================================================
# ADVANCED AI WATERMARK DETECTION - Statistical and Structural Analysis
# Based on: @docs/advanced-ai-watermark-detection.md
# =============================================================================


def analyze_sentence_lengths(text: str) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """
    Calculate sentence length statistics.
    Returns (avg_length, std_dev, median_length) or (None, None, None) if insufficient sentences.
    """
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.split()) > 3]
    
    if len(sentences) < 2:
        return None, None, None
    
    lengths = [len(s.split()) for s in sentences]
    avg_length = statistics.mean(lengths)
    std_dev = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
    median_length = statistics.median(lengths)
    
    return avg_length, std_dev, median_length


def calculate_ttr(text: str) -> float:
    """Calculate Type-Token Ratio (unique words / total words)."""
    words = text.lower().split()
    if not words:
        return 0.0
    unique_words = set(words)
    return len(unique_words) / len(words)


def calculate_mattr(text: str, window_size: int = 100) -> float:
    """Calculate Moving-Average Type-Token Ratio."""
    words = text.lower().split()
    if len(words) < window_size:
        return calculate_ttr(text)
    
    mattr_values = []
    for i in range(len(words) - window_size + 1):
        window = words[i:i+window_size]
        unique = set(window)
        mattr_values.append(len(unique) / window_size)
    
    return statistics.mean(mattr_values) if mattr_values else 0.0


def analyze_heading_hierarchy(text: str) -> Tuple[List[Tuple[int, str]], int]:
    """
    Analyze markdown heading hierarchy.
    Returns (list of (level, title) tuples, consistency_score).
    """
    headings = []
    for match in re.finditer(r'^(#{1,6})\s+(.+)$', text, re.MULTILINE):
        level = len(match.group(1))
        title = match.group(2).strip()
        headings.append((level, title))
    
    if not headings:
        return headings, 0
    
    issues = 0
    prev_level = 0
    for i, (level, title) in enumerate(headings):
        if i == 0:
            if level != 1:
                issues += 1
        else:
            if level > prev_level + 1:
                issues += 1
        prev_level = level
    
    return headings, issues


def analyze_list_uniformity(text: str) -> str:
    """
    Check markdown list marker uniformity.
    Returns 'mixed', 'uniform', or 'none'.
    """
    markers = set()
    for match in re.finditer(r'^\s*([-*+])\s+', text, re.MULTILINE):
        markers.add(match.group(1))
    
    ul_items = re.findall(r'^\s*[-*+]\s+(.+)$', text, re.MULTILINE)
    
    if len(markers) > 1:
        return "mixed"
    elif len(markers) == 1 and ul_items:
        return "uniform"
    else:
        return "none"


def analyze_code_blocks(text: str) -> Optional[float]:
    """
    Analyze code block language tagging.
    Returns ratio of tagged code blocks to total, or None if no code blocks.
    """
    tagged_blocks = re.findall(r'```(\w+)\n([\s\S]+?)```', text)
    untagged_blocks = re.findall(r'```\n([\s\S]+?)```', text)
    
    total_blocks = len(tagged_blocks) + len(untagged_blocks)
    if total_blocks == 0:
        return None
    
    return len(tagged_blocks) / total_blocks


def analyze_markdown_spacing(text: str) -> int:
    """
    Check markdown spacing consistency.
    Returns number of spacing issues found.
    """
    lines = text.split('\n')
    issues = []
    
    for i, line in enumerate(lines):
        if re.match(r'^#{1,6}\s+.+$', line):
            pass
        elif re.match(r'^#{1,6}[^\s].+$', line):
            issues.append(f"Line {i+1}: No space after heading marker")
        elif re.match(r'^#{1,6}\s{2,}.+$', line):
            issues.append(f"Line {i+1}: Multiple spaces after heading marker")
        
        if line.rstrip() != line:
            issues.append(f"Line {i+1}: Trailing whitespace")
    
    return len(issues)


def check_unicode_normalization(text: str) -> str:
    """
    Check if text uses non-NFC Unicode normalization.
    Returns 'non_nfc', 'non_nfd', or 'normalized'.
    """
    nfc_text = unicodedata.normalize('NFC', text)
    nfd_text = unicodedata.normalize('NFD', text)
    
    if text != nfc_text:
        return "non_nfc"
    if text != nfd_text:
        return "non_nfd"
    return "normalized"


def check_bidi_overrides(text: str) -> List[str]:
    """Check for bidirectional override characters."""
    bidi_chars = [
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
        '\u2066', '\u2067', '\u2068', '\u2069'
    ]
    return [c for c in bidi_chars if c in text]


def check_math_alphabetic(text: str) -> List[str]:
    """Check for mathematical alphabetic characters (U+1D400-U+1D7FF)."""
    math_chars = []
    for char in text:
        codepoint = ord(char)
        if 0x1D400 <= codepoint <= 0x1D7FF:
            math_chars.append(char)
    return math_chars


def check_tag_characters(text: str) -> List[str]:
    """Check for tag characters (U+E0000-U+E007F)."""
    tag_chars = []
    for char in text:
        codepoint = ord(char)
        if 0xE0000 <= codepoint <= 0xE007F:
            tag_chars.append(char)
    return tag_chars


def check_prompt_leakage(text: str) -> List[str]:
    """Check for common prompt leakage patterns."""
    prompt_patterns = [
        r'As a \w+',
        r'Write a \w+',
        r'Please compose',
        r'Create a \w+',
        r'You are a \w+',
        r'Act as a \w+',
        r'I need you to',
        r'Your task is to',
        r'In the style of',
        r'Using the following',
        r'Based on the',
        r'Given the',
        r'Make sure to',
        r'Ensure that',
        r'The following is',
    ]
    
    matches = []
    for pattern in prompt_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)
    
    return matches


def check_token_repetition(text: str, n: int = 3, min_repeats: int = 2) -> Dict[str, int]:
    """Check for repeated n-gram sequences."""
    words = text.lower().split()
    ngrams = [tuple(words[i:i+n]) for i in range(len(words)-n+1)]
    ngram_counts = Counter(ngrams)
    
    return {ngram: count for ngram, count in ngram_counts.items() if count >= min_repeats}


def check_eos_patterns(text: str) -> List[str]:
    """Check for end-of-sequence token patterns."""
    eos_patterns = [
        r'<\[im_end\]>',
        r'<\[im_start\]>',
        r'<EOS>',
        r'<END>',
        r'\n\n<',
        r'\|\|',
        r'<\[',
        r'\|>',
    ]
    
    matches = []
    for pattern in eos_patterns:
        if re.search(pattern, text):
            matches.append(pattern)
    
    return matches


def check_statistical_watermarks(text: str) -> Dict[str, Any]:
    """
    Check for statistical and structural AI watermarks.
    Minimal dependencies version (pure Python + built-ins).
    
    Based on: @docs/advanced-ai-watermark-detection.md
    """
    results = {
        'sentence_length_variance': None,
        'sentence_avg_length': None,
        'sentence_median_length': None,
        'ttr': None,
        'mattr': None,
        'heading_hierarchy': None,
        'heading_hierarchy_consistency': None,
        'list_uniformity': None,
        'code_block_tagged_ratio': None,
        'unicode_normalization': None,
        'bidi_overrides': None,
        'math_alphabetic_chars': None,
        'tag_characters': None,
        'prompt_leakage': None,
        'token_repetition': None,
        'eos_patterns': None,
        'markdown_spacing_issues': None,
        'has_statistical_watermark': False,
        'statistical_notes': []
    }
    
    # 1. Sentence Length Variance
    avg_len, std_dev, median_len = analyze_sentence_lengths(text)
    if avg_len is not None:
        results['sentence_avg_length'] = avg_len
        results['sentence_median_length'] = median_len
        results['sentence_length_variance'] = std_dev
        # For technical prose, std_dev < 5 is suspicious
        if std_dev and std_dev < 5:
            results['has_statistical_watermark'] = True
            results['statistical_notes'].append(f"Low sentence length variance (std_dev={std_dev:.1f})")
    
    # 2. Type-Token Ratio
    words = text.lower().split()
    if words:
        ttr = calculate_ttr(text)
        mattr = calculate_mattr(text) if len(words) > 100 else ttr
        results['ttr'] = ttr
        results['mattr'] = mattr
        # Thresholds: TTR < 0.45 for long texts is suspicious
        if len(words) > 1000 and ttr < 0.45:
            results['has_statistical_watermark'] = True
            results['statistical_notes'].append(f"Low TTR ({ttr:.3f})")
        if len(words) > 1000 and mattr < 0.55:
            results['has_statistical_watermark'] = True
            results['statistical_notes'].append(f"Low MATTR ({mattr:.3f})")
    
    # 3. Heading Hierarchy
    headings, consistency_score = analyze_heading_hierarchy(text)
    if headings:
        results['heading_hierarchy'] = [f"H{level}: {title}" for level, title in headings]
        results['heading_hierarchy_consistency'] = consistency_score
        # Perfect hierarchy with >3 headings is AI-like
        if consistency_score == 0 and len(headings) > 3:
            results['has_statistical_watermark'] = True
            results['statistical_notes'].append("Perfect heading hierarchy (AI-like)")
    
    # 4. List Uniformity
    uniformity = analyze_list_uniformity(text)
    results['list_uniformity'] = uniformity
    if uniformity == "uniform":
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append("Uniform list markers (AI-like)")
    
    # 5. Code Block Style
    tagged_ratio = analyze_code_blocks(text)
    results['code_block_tagged_ratio'] = tagged_ratio
    # Human technical writing: tagged_ratio typically > 0.7
    # AI writing: tagged_ratio often < 0.3
    if tagged_ratio is not None and tagged_ratio < 0.3:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Low code block tagging (ratio={tagged_ratio:.2f})")
    
    # 6. Unicode Normalization
    normalization = check_unicode_normalization(text)
    results['unicode_normalization'] = normalization
    if normalization != "normalized":
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Non-normalized Unicode ({normalization})")
    
    # 7. Bidi Overrides
    bidi_chars = check_bidi_overrides(text)
    results['bidi_overrides'] = bidi_chars
    if bidi_chars:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Bidi override chars: {bidi_chars}")
    
    # 8. Mathematical Alphabetic Characters
    math_chars = check_math_alphabetic(text)
    results['math_alphabetic_chars'] = math_chars
    if math_chars:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Math alphabetic chars: {[f'U+{ord(c):04X}' for c in math_chars]}")
    
    # 9. Tag Characters
    tag_chars = check_tag_characters(text)
    results['tag_characters'] = tag_chars
    if tag_chars:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Tag characters: {[f'U+{ord(c):06X}' for c in tag_chars]}")
    
    # 10. Prompt Leakage
    prompt_matches = check_prompt_leakage(text)
    results['prompt_leakage'] = prompt_matches
    if prompt_matches:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Prompt leakage: {prompt_matches[:3]}")
    
    # 11. Token Repetition
    repeated_ngrams = check_token_repetition(text, n=3, min_repeats=2)
    results['token_repetition'] = repeated_ngrams
    # Filter out common phrases
    common_phrases = {"of the", "in the", "to the", "with the", "for the"}
    unusual_repeats = {
        ' '.join(ngram): count 
        for ngram, count in repeated_ngrams.items() 
        if ' '.join(ngram) not in common_phrases
    }
    if unusual_repeats:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"Unusual token repetition: {list(unusual_repeats.keys())[:3]}")
    
    # 12. EOS Patterns
    eos_matches = check_eos_patterns(text)
    results['eos_patterns'] = eos_matches
    if eos_matches:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append(f"EOS patterns: {eos_matches}")
    
    # 13. Markdown Spacing
    spacing_issues = analyze_markdown_spacing(text)
    results['markdown_spacing_issues'] = spacing_issues
    # AI writing: spacing_issues = 0 (too perfect)
    # Only flag if document is long enough (>50 lines)
    if spacing_issues == 0 and len(text.split('\n')) > 50:
        results['has_statistical_watermark'] = True
        results['statistical_notes'].append("Perfect markdown spacing (AI-like)")
    
    return results


# =============================================================================
# ADVANCED WATERMARK DETECTION - Requires spaCy and sentence-transformers
# =============================================================================

def check_advanced_watermarks(text: str) -> Dict[str, Any]:
    """
    Check for advanced AI watermarks using NLP and embeddings.
    Requires spaCy and sentence-transformers.
    
    Based on: @docs/advanced-ai-watermark-detection.md
    """
    results = {
        'pos_ngrams': {},
        'embedding_clustering': None,
        'semantic_drift': None,
        'has_advanced_watermark': False,
        'advanced_notes': []
    }
    
    # 1. POS N-grams (spaCy)
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        doc = nlp(text)
        pos_tags = [token.pos_ for token in doc]
        
        # Count bigrams
        pos_bigrams = [tuple(pos_tags[i:i+2]) for i in range(len(pos_tags)-1)]
        bigram_counts = Counter(pos_bigrams)
        total_bigrams = sum(bigram_counts.values())
        
        # Check for excessive noun-noun bigrams
        nn_count = bigram_counts.get(("NOUN", "NOUN"), 0)
        nn_ratio = nn_count / total_bigrams if total_bigrams > 0 else 0
        results['pos_ngrams']['nn_ratio'] = nn_ratio
        if nn_ratio > 0.1:
            results['has_advanced_watermark'] = True
            results['advanced_notes'].append(f"High noun-noun ratio ({nn_ratio:.3f})")
        
        # Check passive voice
        passive_count = sum(1 for token in doc if token.dep_ == "auxpass")
        verb_count = sum(1 for token in doc if token.pos_ == "VERB")
        passive_ratio = passive_count / verb_count if verb_count > 0 else 0
        results['pos_ngrams']['passive_ratio'] = passive_ratio
        if passive_ratio > 0.3:
            results['has_advanced_watermark'] = True
            results['advanced_notes'].append(f"High passive voice ratio ({passive_ratio:.3f})")
            
        # Check adjective-noun ratio
        adj_noun_count = bigram_counts.get(("ADJ", "NOUN"), 0)
        adj_noun_ratio = adj_noun_count / total_bigrams if total_bigrams > 0 else 0
        results['pos_ngrams']['adj_noun_ratio'] = adj_noun_ratio
        if adj_noun_ratio > 0.15:
            results['has_advanced_watermark'] = True
            results['advanced_notes'].append(f"High adj-noun ratio ({adj_noun_ratio:.3f})")
            
        # Check determiner-noun ratio
        det_noun_count = bigram_counts.get(("DET", "NOUN"), 0)
        det_noun_ratio = det_noun_count / total_bigrams if total_bigrams > 0 else 0
        results['pos_ngrams']['det_noun_ratio'] = det_noun_ratio
        if det_noun_ratio > 0.20:
            results['has_advanced_watermark'] = True
            results['advanced_notes'].append(f"High det-noun ratio ({det_noun_ratio:.3f})")
            
    except ImportError:
        results['advanced_notes'].append("spaCy not installed; POS checks skipped")
    except Exception as e:
        results['advanced_notes'].append(f"POS analysis error: {str(e)}")
    
    # 2. Embedding Clustering (sentence-transformers)
    try:
        from sentence_transformers import SentenceTransformer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
        
        model = SentenceTransformer("all-MiniLM-L6-v2")
        words = text.split()
        chunks = [" ".join(words[i:i+500]) for i in range(0, len(words), 500)]
        
        if len(chunks) > 1:
            embeddings = model.encode(chunks)
            sim_matrix = cosine_similarity(embeddings)
            np.fill_diagonal(sim_matrix, 0)
            avg_sim = sim_matrix.mean()
            results['embedding_clustering'] = avg_sim
            # Human writing: avg_sim typically < 0.8
            # AI writing: avg_sim typically > 0.85
            if avg_sim > 0.85:
                results['has_advanced_watermark'] = True
                results['advanced_notes'].append(f"Tight embedding cluster (avg_sim={avg_sim:.3f})")
    except ImportError:
        results['advanced_notes'].append("sentence-transformers not installed; embedding checks skipped")
    except Exception as e:
        results['advanced_notes'].append(f"Embedding analysis error: {str(e)}")
    
    # 3. Semantic Drift
    try:
        from sentence_transformers import SentenceTransformer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
        
        model = SentenceTransformer("all-MiniLM-L6-v2")
        
        # Extract topic from first 3 sentences
        sentences = re.split(r'[.!?]+', text)
        topic_sentences = sentences[:3]
        topic = " ".join([s.strip() for s in topic_sentences if s.strip()])
        
        if topic:
            topic_embedding = model.encode([topic])
            words = text.split()
            chunks = [" ".join(words[i:i+500]) for i in range(0, len(words), 500)]
            chunk_embeddings = model.encode(chunks)
            
            similarities = cosine_similarity(chunk_embeddings, topic_embedding).flatten()
            avg_sim = similarities.mean()
            results['semantic_drift'] = avg_sim
            # Human writing: avg_sim to topic typically 0.6-0.75
            # AI writing: avg_sim to topic typically > 0.8
            if avg_sim > 0.8:
                results['has_advanced_watermark'] = True
                results['advanced_notes'].append(f"Low semantic drift (avg_sim={avg_sim:.3f})")
    except ImportError:
        pass  # Already noted above
    except Exception as e:
        results['advanced_notes'].append(f"Semantic drift analysis error: {str(e)}")
    
    return results


def check_file_for_watermarks(filepath: str, check_statistical: bool = True, check_advanced: bool = False) -> Dict[str, Any]:
    """
    Check a file for AI watermarks with improved detection logic.
    
    Args:
        filepath: Path to the file to check
        check_statistical: Whether to run statistical/structural checks (default: True)
        check_advanced: Whether to run advanced NLP checks (default: False, requires spaCy/sentence-transformers)
    
    Returns dict with detection results.
    """
    file_type = get_file_type(filepath)
    
    results = {
        'file': filepath,
        'file_type': file_type,
        'size': os.path.getsize(filepath),
        'zero_width': {},
        'variation_selectors': 0,
        'c2pa_metadata': False,
        'c2pa_indicators': [],
        'c2pa_structural': [],
        'homoglyphs': [],
        'suspicious_homoglyphs': [],  # NEW: Only homoglyphs in suspicious context
        'has_watermark': False,
        'notes': [],
    }
    
    try:
        # Handle binary files differently
        if file_type in ('png', 'jpg', 'binary'):
            binary_results = check_binary_c2pa(filepath)
            results.update(binary_results)
            if results.get('binary_c2pa_detected'):
                results['c2pa_metadata'] = True
                results['has_watermark'] = True
                results['notes'].append('Binary C2PA (JUMBF) detected')
            if results.get('jumbf_found'):
                results['notes'].append('JUMBF container detected')
            return results
        
        # For text-based files (SVG, text files)
        with open(filepath, 'rb') as f:
            raw = f.read()
        
        # Try UTF-8 first, fall back to latin-1
        try:
            content = raw.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = raw.decode('utf-16', errors='replace')
            except UnicodeDecodeError:
                content = raw.decode('latin-1', errors='replace')
        
        # Check zero-width characters
        for char in ZERO_WIDTH_CHARS:
            count = content.count(char)
            if count > 0:
                results['zero_width'][f'U+{ord(char):04X}'] = count
                results['has_watermark'] = True
        
        # Check variation selectors
        for char in VARIATION_SELECTORS:
            count = content.count(char)
            if count > 0:
                results['variation_selectors'] += count
                results['has_watermark'] = True
        
        # =========================================================================
        # IMPROVED: Specific C2PA structural detection
        # =========================================================================
        
        # Check for C2PA namespace URLs
        content_lower = content.lower()
        for ns_url in C2PA_NAMESPACE_URLS:
            if ns_url in content_lower:
                results['c2pa_metadata'] = True
                results['c2pa_structural'].append(f'namespace:{ns_url}')
                results['has_watermark'] = True
        
        # Check for C2PA structural patterns using regex
        for pattern in C2PA_STRUCTURAL_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                results['c2pa_metadata'] = True
                results['c2pa_structural'].append(f'pattern:{pattern}')
                results['has_watermark'] = True
        
        # Check legacy C2PA indicators (but don't mark as watermark by themselves)
        for indicator in C2PA_LEGACY_INDICATORS:
            if indicator in content_lower:
                # Only add to indicators if we also found structural C2PA
                if results['c2pa_structural']:
                    results['c2pa_indicators'].append(indicator)
        
        # =========================================================================
        # IMPROVED: Context-aware homoglyph detection
        # =========================================================================
        
        # Find all homoglyph characters
        homoglyph_positions = []
        for i, char in enumerate(content):
            if char in HOMOGLYPH_MAP:
                homoglyph_positions.append(i)
        
        # For each homoglyph, check context
        for pos in homoglyph_positions:
            char = content[pos]
            latin_equiv = HOMOGLYPH_MAP[char]
            
            homoglyph_info = {
                'char': char,
                'codepoint': f'U+{ord(char):04X}',
                'latin_equivalent': latin_equiv,
                'position': pos
            }
            
            # Always record all homoglyphs found
            results['homoglyphs'].append(homoglyph_info)
            
            # NEW: Check if this is in a suspicious (watermark-like) context
            if is_homoglyph_in_latin_context(content, pos):
                results['suspicious_homoglyphs'].append(homoglyph_info)
                results['has_watermark'] = True
        
        # Add notes if we found homoglyphs but none were suspicious
        if results['homoglyphs'] and not results['suspicious_homoglyphs']:
            results['notes'].append(
                f"Found {len(results['homoglyphs'])} homoglyph chars but all appear "
                f"in legitimate foreign language context, not watermarks"
            )
        
        # =========================================================================
        # NEW: Advanced AI Watermark Detection (Statistical & Structural)
        # =========================================================================
        
        # Only run on text/markdown files with sufficient content
        if check_statistical and file_type in ('text', 'svg', 'md') and len(content) > 100:
            statistical_results = check_statistical_watermarks(content)
            results.update(statistical_results)
            
            # Update overall has_watermark flag
            if statistical_results.get('has_statistical_watermark'):
                results['has_watermark'] = True
            
            # Merge notes
            for note in statistical_results.get('statistical_notes', []):
                if note not in results['notes']:
                    results['notes'].append(note)
        
        # Run advanced checks if requested
        if check_advanced and file_type in ('text', 'svg', 'md') and len(content) > 500:
            try:
                advanced_results = check_advanced_watermarks(content)
                results.update(advanced_results)
                
                # Update overall has_watermark flag
                if advanced_results.get('has_advanced_watermark'):
                    results['has_watermark'] = True
                
                # Merge notes
                for note in advanced_results.get('advanced_notes', []):
                    if note not in results['notes']:
                        results['notes'].append(note)
            except Exception as e:
                results['notes'].append(f"Advanced watermark check error: {str(e)}")
        
        return results
    
    except Exception as e:
        return {
            'file': filepath,
            'file_type': file_type,
            'error': str(e),
            'notes': ['Error processing file']
        }


def scan_directory(directory: str, include_binary: bool = True, check_statistical: bool = True, check_advanced: bool = False) -> List[Dict[str, Any]]:
    """Scan all files in a directory for AI watermarks."""
    results = []
    
    for filepath in Path(directory).rglob('*'):
        if filepath.is_file() and not filepath.name.startswith('.'):
            # Skip the script itself and common non-content files
            if filepath.name == 'ai_watermark_scanner.py':
                continue
            if filepath.name == '.DS_Store':
                continue
            
            result = check_file_for_watermarks(str(filepath), check_statistical=check_statistical, check_advanced=check_advanced)
            
            # Always include files with findings
            if result.get('has_watermark'):
                results.append(result)
            # Include files with errors
            elif 'error' in result:
                results.append(result)
            # Include files with notes (even if no watermark)
            elif result.get('notes'):
                results.append(result)
            # For binary files, include if we found JUMBF or other markers
            elif result.get('jumbf_found') or result.get('c2pa_brand_found'):
                results.append(result)
            # Include files with statistical findings
            elif result.get('has_statistical_watermark'):
                results.append(result)
            # Include files with advanced findings
            elif result.get('has_advanced_watermark'):
                results.append(result)
    
    return results


def print_results(findings: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Print scan results in a readable format."""
    
    if not findings:
        print("No watermarks or notable findings detected.")
        return
    
    print(f"\nFound {len(findings)} files with findings:\n")
    
    for f in findings:
        print(f"  {'='*60}")
        print(f"  FILE: {f['file']}")
        print(f"  Type: {f.get('file_type', 'unknown')}")
        
        # Zero-width characters
        if f.get('zero_width'):
            print(f"  ZERO-WIDTH CHARS: {f['zero_width']}")
        
        # Variation selectors
        if f.get('variation_selectors', 0) > 0:
            print(f"  VARIATION SELECTORS: {f['variation_selectors']}")
        
        # C2PA metadata
        if f.get('c2pa_metadata'):
            print(f"  C2PA METADATA: DETECTED")
            if f.get('c2pa_structural'):
                print(f"    Structural indicators: {f['c2pa_structural'][:3]}")  # Limit output
            if f.get('c2pa_indicators'):
                print(f"    Legacy indicators: {f['c2pa_indicators']}")
        
        # Binary C2PA
        if f.get('binary_c2pa_detected'):
            print(f"  BINARY C2PA: DETECTED (JUMBF format)")
        elif f.get('jumbf_found'):
            print(f"  JUMBF CONTAINER: DETECTED")
        
        # Homoglyphs
        if f.get('suspicious_homoglyphs'):
            print(f"  SUSPICIOUS HOMOGLYPHS: {len(f['suspicious_homoglyphs'])}")
            if verbose:
                for h in f['suspicious_homoglyphs'][:5]:  # Show first 5
                    print(f"    {h['char']} ({h['codepoint']}) -> '{h['latin_equivalent']}' at pos {h['position']}")
                if len(f['suspicious_homoglyphs']) > 5:
                    print(f"    ... and {len(f['suspicious_homoglyphs']) - 5} more")
        
        elif f.get('homoglyphs'):
            # Only non-suspicious homoglyphs found
            if verbose:
                print(f"  HOMOGLYPHS (legitimate foreign text): {len(f['homoglyphs'])}")
        
        # =========================================================================
        # NEW: Statistical Watermark Findings
        # =========================================================================
        
        # Sentence length statistics
        if f.get('sentence_length_variance') is not None:
            std_dev = f['sentence_length_variance']
            avg_len = f.get('sentence_avg_length', 'N/A')
            median_len = f.get('sentence_median_length', 'N/A')
            flag = " [FLAG: low variance]" if f.get('has_statistical_watermark') and any("sentence length variance" in n for n in f.get('statistical_notes', [])) else ""
            print(f"  SENTENCE STATS: avg={avg_len:.1f} words, median={median_len:.1f}, std_dev={std_dev:.1f}{flag}")
        
        # TTR and MATTR
        if f.get('ttr') is not None:
            ttr = f['ttr']
            mattr = f.get('mattr', 'N/A')
            flag = " [FLAG: low lexical diversity]" if f.get('has_statistical_watermark') and any("TTR" in n or "MATTR" in n for n in f.get('statistical_notes', [])) else ""
            mattr_str = f"{mattr:.3f}" if isinstance(mattr, (int, float)) else mattr
            print(f"  LEXICAL DIVERSITY: TTR={ttr:.3f}, MATTR={mattr_str}{flag}")
        
        # Heading hierarchy
        if f.get('heading_hierarchy'):
            headings = f['heading_hierarchy']
            consistency = f.get('heading_hierarchy_consistency', 0)
            flag = " [FLAG: perfect hierarchy]" if consistency == 0 and len(headings) > 3 else ""
            print(f"  HEADING HIERARCHY: {len(headings)} headings, {consistency} issues{flag}")
            if verbose:
                for h in headings[:5]:
                    print(f"    {h}")
        
        # List uniformity
        if f.get('list_uniformity'):
            uniformity = f['list_uniformity']
            flag = " [FLAG: AI-like]" if uniformity == "uniform" else ""
            print(f"  LIST UNIFORMITY: {uniformity}{flag}")
        
        # Code block tagging
        if f.get('code_block_tagged_ratio') is not None:
            ratio = f['code_block_tagged_ratio']
            flag = " [FLAG: low tagging]" if ratio < 0.3 else ""
            print(f"  CODE BLOCK TAGGING: {ratio:.2f}{flag}")
        
        # Unicode normalization
        if f.get('unicode_normalization'):
            norm = f['unicode_normalization']
            flag = " [FLAG]" if norm != "normalized" else ""
            print(f"  UNICODE NORMALIZATION: {norm}{flag}")
        
        # Bidi overrides
        if f.get('bidi_overrides'):
            bidi = f['bidi_overrides']
            print(f"  BIDI OVERRIDES: {bidi} [FLAG]")
        
        # Math alphabetic characters
        if f.get('math_alphabetic_chars'):
            math_chars = f['math_alphabetic_chars']
            print(f"  MATH ALPHABETIC CHARS: {[f'U+{ord(c):04X}' for c in math_chars]} [FLAG]")
        
        # Tag characters
        if f.get('tag_characters'):
            tag_chars = f['tag_characters']
            print(f"  TAG CHARACTERS: {[f'U+{ord(c):06X}' for c in tag_chars]} [FLAG]")
        
        # Prompt leakage
        if f.get('prompt_leakage'):
            prompts = f['prompt_leakage']
            print(f"  PROMPT LEAKAGE: {prompts[:3]} [FLAG]")
        
        # Token repetition
        if f.get('token_repetition') and f['token_repetition']:
            repeats = f['token_repetition']
            common_phrases = {"of the", "in the", "to the", "with the", "for the"}
            unusual = {k: v for k, v in repeats.items() if k not in common_phrases}
            if unusual:
                print(f"  TOKEN REPETITION: {list(unusual.keys())[:3]} [FLAG]")
        
        # EOS patterns
        if f.get('eos_patterns'):
            eos = f['eos_patterns']
            print(f"  EOS PATTERNS: {eos} [FLAG]")
        
        # Markdown spacing
        if f.get('markdown_spacing_issues') is not None:
            issues = f['markdown_spacing_issues']
            flag = " [FLAG: too perfect]" if issues == 0 and f.get('file_type') in ('text', 'md') and f.get('statistical_notes', []).count("Perfect markdown spacing") > 0 else ""
            print(f"  MARKDOWN SPACING: {issues} issues{flag}")
        
        # =========================================================================
        # NEW: Advanced Watermark Findings (spaCy, sentence-transformers)
        # =========================================================================
        
        # POS n-grams
        if f.get('pos_ngrams'):
            pos = f['pos_ngrams']
            flags = []
            if pos.get('nn_ratio', 0) > 0.1:
                flags.append(f"high NN ratio: {pos['nn_ratio']:.3f}")
            if pos.get('passive_ratio', 0) > 0.3:
                flags.append(f"high passive: {pos['passive_ratio']:.3f}")
            if pos.get('adj_noun_ratio', 0) > 0.15:
                flags.append(f"high ADJ-NOUN: {pos['adj_noun_ratio']:.3f}")
            if pos.get('det_noun_ratio', 0) > 0.20:
                flags.append(f"high DET-NOUN: {pos['det_noun_ratio']:.3f}")
            if flags:
                print(f"  POS NGRAMS: {', '.join(flags)} [FLAG]")
            elif verbose:
                print(f"  POS NGRAMS: nn={pos.get('nn_ratio', 0):.3f}, passive={pos.get('passive_ratio', 0):.3f}, adj-noun={pos.get('adj_noun_ratio', 0):.3f}, det-noun={pos.get('det_noun_ratio', 0):.3f}")
        
        # Embedding clustering
        if f.get('embedding_clustering') is not None:
            sim = f['embedding_clustering']
            flag = " [FLAG: tight cluster]" if sim > 0.85 else ""
            print(f"  EMBEDDING CLUSTERING: avg_sim={sim:.3f}{flag}")
        
        # Semantic drift
        if f.get('semantic_drift') is not None:
            drift = f['semantic_drift']
            flag = " [FLAG: low drift]" if drift > 0.8 else ""
            print(f"  SEMANTIC DRIFT: avg_sim_to_topic={drift:.3f}{flag}")
        
        # Notes
        if f.get('notes'):
            for note in f['notes']:
                print(f"  NOTE: {note}")
        
        # Errors
        if 'error' in f:
            print(f"  ERROR: {f['error']}")
        
        print()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scan files for AI watermarks with improved detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ai_watermark_scanner.py /path/to/directory
  python3 ai_watermark_scanner.py --verbose file.svg
  python3 ai_watermark_scanner.py --binary-check image.png
  python3 ai_watermark_scanner.py --advanced /path/to/check
  python3 ai_watermark_scanner.py --no-statistical file.md
        """
    )
    parser.add_argument(
        'target',
        nargs='?',
        default='.',
        help='File or directory to scan (default: current directory)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information about findings'
    )
    parser.add_argument(
        '-b', '--binary-check',
        action='store_true',
        help='Force binary file check (for images)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '-s', '--statistical',
        action='store_true',
        default=True,
        help='Run statistical and structural watermark checks (default: True)'
    )
    parser.add_argument(
        '--no-statistical',
        action='store_true',
        default=False,
        help='Skip statistical and structural watermark checks'
    )
    parser.add_argument(
        '-a', '--advanced',
        action='store_true',
        default=False,
        help='Run advanced watermark checks (requires spaCy and sentence-transformers)'
    )
    
    args = parser.parse_args()
    
    # Resolve statistical flag: on by default, off if --no-statistical
    check_statistical = not args.no_statistical
    
    print(f"Scanning: {args.target}")
    if args.advanced:
        print("  [Advanced checks: ENABLED (requires spaCy, sentence-transformers)]")
    if check_statistical:
        print("  [Statistical checks: ENABLED]")
    else:
        print("  [Statistical checks: DISABLED]")
    print()
    
    if os.path.isfile(args.target):
        # Single file check
        if args.binary_check or args.target.lower().endswith(('.png', '.jpg', '.jpeg')):
            # Force binary check
            findings = [check_file_for_watermarks(args.target, check_statistical=False, check_advanced=False)]
        else:
            findings = [check_file_for_watermarks(args.target, check_statistical=check_statistical, check_advanced=args.advanced)]
    else:
        # Directory scan
        findings = scan_directory(args.target, check_statistical=check_statistical, check_advanced=args.advanced)
    
    if args.json:
        import json
        print(json.dumps(findings, indent=2, ensure_ascii=False, default=str))
    else:
        print_results(findings, verbose=args.verbose)
    
    # Return exit code: 0 = no watermarks, 1 = watermarks found
    if any(f.get('has_watermark', False) for f in findings):
        sys.exit(1)
    elif any(f.get('has_statistical_watermark', False) for f in findings):
        sys.exit(1)
    elif any(f.get('has_advanced_watermark', False) for f in findings):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
