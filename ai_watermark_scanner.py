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
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


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


def check_file_for_watermarks(filepath: str) -> Dict[str, Any]:
    """
    Check a file for AI watermarks with improved detection logic.
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
        
        return results
    
    except Exception as e:
        return {
            'file': filepath,
            'file_type': file_type,
            'error': str(e),
            'notes': ['Error processing file']
        }


def scan_directory(directory: str, include_binary: bool = True) -> List[Dict[str, Any]]:
    """Scan all files in a directory for AI watermarks."""
    results = []
    
    for filepath in Path(directory).rglob('*'):
        if filepath.is_file() and not filepath.name.startswith('.'):
            # Skip the script itself and common non-content files
            if filepath.name == 'ai_watermark_scanner.py':
                continue
            if filepath.name == '.DS_Store':
                continue
            
            result = check_file_for_watermarks(str(filepath))
            
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
    
    args = parser.parse_args()
    
    print(f"Scanning: {args.target}")
    
    if os.path.isfile(args.target):
        # Single file check
        if args.binary_check or args.target.lower().endswith(('.png', '.jpg', '.jpeg')):
            # Force binary check
            findings = [check_file_for_watermarks(args.target)]
        else:
            findings = [check_file_for_watermarks(args.target)]
    else:
        # Directory scan
        findings = scan_directory(args.target)
    
    if args.json:
        import json
        print(json.dumps(findings, indent=2, ensure_ascii=False, default=str))
    else:
        print_results(findings, verbose=args.verbose)
    
    # Return exit code: 0 = no watermarks, 1 = watermarks found
    if any(f.get('has_watermark', False) for f in findings):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
