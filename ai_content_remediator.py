#!/usr/bin/env python3
"""
AI Content Remediator

Automatically fixes common AI-generated content issues detected by ai_watermark_scanner.py:
- Cleans up HTML/XML comment blocks
- Normalizes markdown spacing between elements
- Detects token repetition patterns for manual review
- Preserves internal notes and metadata sections

Usage:
    python3 ai_content_remediator.py input.md [output.md]
    python3 ai_content_remediator.py input.md --diff
    python3 ai_content_remediator.py input.md --in-place

Flags:
    --diff          Show diff instead of saving (default)
    --in-place      Overwrite input file (use with caution)
    --verbose       Show detailed information
    --dry-run       Check without making changes
"""

import sys
import re
import difflib
from pathlib import Path
from typing import List, Tuple, Optional


# =============================================================================
# CONFIGURATION
# =============================================================================

# Patterns for HTML/XML comments to clean
HTML_COMMENT_PATTERN = re.compile(
    r'^\s*<!--\s*(.*?)\s*--->\s*$',
    re.MULTILINE | re.DOTALL
)

# Markdown element patterns for spacing normalization
HEADING_PATTERN = re.compile(r'^#{1,6}\s+.+$', re.MULTILINE)
LIST_PATTERN = re.compile(r'^\s*[-*+]\s+|^\s*\d+\.\s+', re.MULTILINE)
HORIZONTAL_RULE_PATTERN = re.compile(r'^(---|\*\*\*|___)\s*$', re.MULTILINE)
CODE_BLOCK_PATTERN = re.compile(r'^```.*?$|^~~~.*?$', re.MULTILINE | re.DOTALL)

# Token repetition: detect 3-gram patterns that repeat unusually
# This matches sequences like "case study: taking" that appear in AI-generated text
TOKEN_REPETITION_PATTERN = re.compile(
    r'\b(\w+\s+\w+\s+\w+)\b.*?\b\1\b',
    re.IGNORECASE | re.DOTALL
)

# More specific: consecutive word sequences that sound unnatural
# Like "taking over an" appearing multiple times in close proximity
CONSECUTIVE_TOKEN_PATTERN = re.compile(
    r'(\b\w+\s+){2,3}(\w+\b)(?:\s+\1\2)?',
    re.IGNORECASE
)

# Prompt leakage patterns - more specific to AI prompts
# Only match when the role word is a typical AI prompt role
AI_ROLE_WORDS = [
    'writer', 'author', 'developer', 'expert', 'specialist', 'consultant',
    'professional', 'analyst', 'assistant', 'blogger', 'copywriter',
    'journalist', 'marketer', 'designer', 'engineer', 'programmer',
    'content', 'creator', 'editor', 'translator', 'researcher'
]

PROMPT_LEAKAGE_PATTERNS = [
    (re.compile(r'\bAs a\s+(' + '|'.join(AI_ROLE_WORDS) + r')\b', re.IGNORECASE), 
     "'As a [AI role]' prompt leakage"),
    (re.compile(r'\bAs an\s+(' + '|'.join(AI_ROLE_WORDS) + r')\b', re.IGNORECASE), 
     "'As an [AI role]' prompt leakage"),
    (re.compile(r'\bI am a\s+(' + '|'.join(AI_ROLE_WORDS) + r')\b', re.IGNORECASE), 
     "'I am a [AI role]' prompt leakage"),
    (re.compile(r'\bYou are a\s+(' + '|'.join(AI_ROLE_WORDS) + r')\b', re.IGNORECASE), 
     "'You are a [AI role]' prompt leakage"),
]

# Internal notes section marker (to preserve)
INTERNAL_NOTES_MARKER = '## Internal notes'


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def read_file(filepath: str) -> str:
    """Read file content."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def write_file(filepath: str, content: str) -> None:
    """Write content to file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


def detect_html_comments(content: str) -> List[Tuple[int, int, str]]:
    """Find all HTML comment blocks with their positions."""
    comments = []
    for match in HTML_COMMENT_PATTERN.finditer(content):
        comments.append((match.start(), match.end(), match.group(1)))
    return comments


def remove_html_comments(content: str) -> str:
    """Remove all HTML comments from content."""
    return re.sub(r'^\s*<!--.*?-->\s*$', '', content, flags=re.MULTILINE)


def clean_html_comments(content: str, verbose: bool = False, remove: bool = False) -> Tuple[str, int]:
    """
    Clean HTML comment blocks.
    
    Strategy:
    - If remove=True: Remove all HTML comments
    - Otherwise: Reformat them properly
    
    Returns (cleaned_content, num_changes)
    """
    if remove:
        cleaned = remove_html_comments(content)
        # Count how many lines were removed
        changes = content.count('<!--')
        # Clean up multiple blank lines
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        cleaned = cleaned.strip() + '\n'
        return cleaned, changes
    
    lines = content.split('\n')
    cleaned_lines = []
    comment_block_start = None
    comment_block_lines = []
    changes = 0
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check if line is an HTML comment
        comment_match = re.match(r'^\s*<!--\s*(.*?)\s*-->\s*$', line)
        
        if comment_match:
            # Start or continue a comment block
            if comment_block_start is None:
                comment_block_start = i
            comment_block_lines.append(comment_match.group(1).strip())
            i += 1
            continue
        else:
            # End of comment block
            if comment_block_start is not None:
                # We have a comment block to process
                if comment_block_start == 0 and i > 0:
                    # Comments at the very start - check if they're metadata
                    # metadata comments often look like: SUGGESTED POST SLUG, etc.
                    if any('SUGGESTED' in l.upper() for l in comment_block_lines):
                        # This is a metadata block - ensure proper spacing
                        if verbose:
                            print(f"  Found metadata block with {len(comment_block_lines)} lines")
                        
                        cleaned_lines.append('')  # Blank line before
                        for meta_line in comment_block_lines:
                            if meta_line:
                                cleaned_lines.append(f"<!-- {meta_line} -->")
                        cleaned_lines.append('')  # Blank line after
                        changes += 1
                    else:
                        # Regular comments at start - keep them
                        for cb_line in comment_block_lines:
                            if cb_line:
                                cleaned_lines.append(f"<!-- {cb_line} -->")
                        cleaned_lines.append('')
                        changes += 1
                else:
                    # Comments in the middle of content - keep them
                    for cb_line in comment_block_lines:
                        if cb_line:
                            cleaned_lines.append(f"<!-- {cb_line} -->")
                    changes += 1
                
                comment_block_start = None
                comment_block_lines = []
            
            cleaned_lines.append(line)
        
        i += 1
    
    # Handle trailing comment block
    if comment_block_start is not None:
        for cb_line in comment_block_lines:
            if cb_line:
                cleaned_lines.append(f"<!-- {cb_line} -->")
        changes += 1
    
    # Filter out excessive blank lines
    cleaned_content = '\n'.join(cleaned_lines)
    
    # Remove leading/trailing whitespace
    cleaned_content = cleaned_content.strip() + '\n'
    
    return cleaned_content, changes


def normalize_markdown_spacing(content: str, verbose: bool = False) -> Tuple[str, int]:
    """
    Normalize spacing between markdown elements.
    
    Rules:
    - 1 blank line between paragraphs
    - 1 blank line before/after headings
    - 1 blank line before/after lists
    - 1 blank line before/after horizontal rules
    - 0 blank lines within lists
    - 2 blank lines before major sections (H1, H2)
    
    Returns (normalized_content, num_changes)
    """
    lines = content.split('\n')
    normalized = []
    changes = 0
    prev_type = None  # 'paragraph', 'heading', 'list', 'rule', 'code', 'blank'
    
    # Classify each line
    classified = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            classified.append(('blank', line))
        elif stripped.startswith('#'):
            heading_level = len(stripped.split()[0])
            classified.append(('heading', line, heading_level))
        elif stripped.startswith(('---', '***', '___')) and len(stripped) <= 5:
            classified.append(('rule', line))
        elif stripped.startswith(('```', '~~~')):
            classified.append(('code_fence', line))
        elif re.match(r'^\s*[-*+]\s+|^\s*\d+\.\s+', stripped):
            classified.append(('list', line))
        else:
            classified.append(('paragraph', line))
    
    # Rebuild with proper spacing
    i = 0
    while i < len(classified):
        item = classified[i]
        item_type = item[0]
        # Extract line: it's the second element for all types
        line = item[1] if len(item) > 1 else ''
        
        if item_type == 'blank':
            # Check if we need this blank line
            if i > 0 and i < len(classified) - 1:
                prev = classified[i-1]
                next_item = classified[i+1]
                
                # Determine if blank line is needed
                needs_blank = should_have_blank_line(prev, next_item)
                
                if needs_blank:
                    normalized.append('')
                # else: skip this blank line
            i += 1
            continue
        
        # Add the line itself
        if isinstance(line, str):
            normalized.append(line.rstrip())
        else:
            normalized.append('')
        
        # Add blank line after if needed
        if i < len(classified) - 1:
            current = item
            next_item = classified[i+1]
            
            if should_have_blank_line(current, next_item):
                # Will be added when we process the next blank, or we add it now
                pass
        
        i += 1
    
    # Post-process: ensure proper spacing
    result = '\n'.join(normalized)
    
    # Clean up multiple blank lines
    result = re.sub(r'\n{3,}', '\n\n', result)
    
    # Ensure file ends with single newline
    result = result.rstrip() + '\n'
    
    # Count changes (rough estimate)
    if result != content:
        changes = 1
    
    return result, changes


def should_have_blank_line(current, next_item) -> bool:
    """Determine if a blank line should exist between current and next."""
    current_type = current[0]
    next_type = next_item[0]
    
    # No blank within code blocks
    if current_type == 'code_fence' or next_type == 'code_fence':
        return False
    
    # No blank within lists
    if current_type == 'list' and next_type == 'list':
        return False
    
    # Blank line before headings
    if next_type == 'heading':
        return True
    
    # Blank line after headings
    if current_type == 'heading':
        return True
    
    # Blank line before/after rules
    if next_type == 'rule' or current_type == 'rule':
        return True
    
    # Blank line before lists
    if next_type == 'list' and current_type not in ('list', 'blank'):
        return True
    
    # Blank line between paragraphs
    if current_type == 'paragraph' and next_type == 'paragraph':
        return True
    
    # Blank line between different element types
    if current_type != next_type and current_type not in ('blank',) and next_type not in ('blank',):
        return True
    
    return False


def detect_token_repetition(content: str, verbose: bool = False) -> List[Tuple[str, List[int]]]:
    """
    Detect repetitive token sequences (3-grams) that appear in close proximity.
    
    Only reports sequences that:
    - Appear at least 3 times in the document, OR
    - Appear at least 2 times within 15 words of each other
    
    Returns list of (repeated_sequence, [positions])
    """
    # Common English trigrams that should be ignored
    COMMON_ENGLISH_TRIGRAMS = {
        'and the', 'the and', 'in the', 'the in', 'to the', 'the to',
        'of the', 'the of', 'for the', 'that the', 'this the',
        'with the', 'from the', 'on the', 'at the', 'by the',
        'as a', 'as the', 'it is', 'is a', 'was the',
        'php 8', '8 0', '8 4', '4 0',
    }
    
    # Split into words (preserving punctuation attached to words)
    words = re.findall(r'\b\w+[\w\-]*\b|[.,;!?]', content.lower())
    
    # Find 3-gram sequences
    trigrams = []
    for i in range(len(words) - 2):
        trigram = ' '.join(words[i:i+3])
        trigrams.append((trigram, i))
    
    # Count occurrences
    trigram_counts = {}
    for trigram, pos in trigrams:
        if trigram not in trigram_counts:
            trigram_counts[trigram] = []
        trigram_counts[trigram].append(pos)
    
    # Filter for repetitive patterns
    repetitive = []
    for trigram, positions in trigram_counts.items():
        # Remove all punctuation for comparison
        trigram_clean = re.sub(r'[^\w\s]', '', trigram).strip()
        trigram_clean = re.sub(r'\s+', ' ', trigram_clean)
        
        # Skip if trigram is empty or too short after cleaning
        if not trigram_clean or len(trigram_clean.split()) < 2:
            continue
        
        # Skip common English patterns (check both original and cleaned)
        if trigram_clean in COMMON_ENGLISH_TRIGRAMS or trigram in COMMON_ENGLISH_TRIGRAMS:
            continue
        
        # Skip trigrams that contain only very common words
        words_in_trigram = trigram_clean.split()
        if len(words_in_trigram) < 2:
            continue
        
        # Skip if all words are very common
        common_words = {'the', 'and', 'in', 'to', 'of', 'for', 'that', 'this', 
                       'with', 'from', 'on', 'at', 'by', 'as', 'is', 'was', 'a', 'an',
                       'it', 'be', 'are', 'have', 'has', 'had', 'but', 'not'}
        if all(w.lower() in common_words for w in words_in_trigram):
            continue
        
        # Skip numeric sequences like version numbers
        if all(w.isdigit() or w in {'.', '-'} for w in words_in_trigram):
            continue
        
        if len(positions) >= 3:
            # Appears at least 3 times
            repetitive.append((trigram, positions))
        elif len(positions) >= 2:
            # Check if any two appearances are close together
            for i in range(len(positions) - 1):
                if positions[i+1] - positions[i] < 15:
                    repetitive.append((trigram, positions))
                    break
    
    # Sort by frequency
    repetitive.sort(key=lambda x: len(x[1]), reverse=True)
    
    # Only return top 10 to avoid overwhelming output
    return repetitive[:10]


def detect_prompt_leakage(content: str, verbose: bool = False) -> List[Tuple[str, int, str]]:
    """
    Detect prompt leakage patterns.
    
    Returns list of (matched_text, position, pattern_name)
    """
    findings = []
    for pattern, name in PROMPT_LEAKAGE_PATTERNS:
        for match in pattern.finditer(content):
            findings.append((match.group(), match.start(), name))
    return findings


def preserve_internal_notes(content: str) -> Tuple[str, List[str]]:
    """
    Identify and preserve internal notes sections.
    
    Returns (content_with_markers, list_of_notes_sections)
    """
    # Find internal notes sections
    notes_sections = []
    lines = content.split('\n')
    
    in_notes = False
    notes_start = None
    notes_lines = []
    
    for i, line in enumerate(lines):
        if INTERNAL_NOTES_MARKER in line:
            if not in_notes:
                in_notes = True
                notes_start = i
                notes_lines = [line]
            else:
                # End of notes section
                in_notes = False
                notes_sections.append((notes_start, i, '\n'.join(notes_lines)))
                notes_lines = []
        elif in_notes:
            notes_lines.append(line)
    
    # Handle trailing notes
    if in_notes and notes_lines:
        notes_sections.append((notes_start, len(lines), '\n'.join(notes_lines)))
    
    return content, notes_sections


# =============================================================================
# MAIN REMEDIATION FUNCTION
# =============================================================================

def remediate_content(content: str, verbose: bool = False, remove_comments: bool = False) -> Tuple[str, dict]:
    """
    Apply all remediation fixes to content.
    
    Returns (remediated_content, report_dict)
    """
    original = content
    report = {
        'html_comments_cleaned': 0,
        'spacing_normalized': 0,
        'token_repetitions_found': [],
        'prompt_leakage_found': [],
        'internal_notes_preserved': 0
    }
    
    # Step 1: Preserve internal notes
    content, notes_sections = preserve_internal_notes(content)
    report['internal_notes_preserved'] = len(notes_sections)
    
    # Step 2: Clean HTML comments (or remove them)
    content, cleaned_count = clean_html_comments(content, verbose, remove=remove_comments)
    report['html_comments_cleaned'] = cleaned_count
    
    # Step 3: Normalize markdown spacing
    content, spacing_count = normalize_markdown_spacing(content, verbose)
    report['spacing_normalized'] = spacing_count
    
    # Step 4: Detect issues for manual review (non-destructive detection)
    report['token_repetitions_found'] = detect_token_repetition(content, verbose)
    report['prompt_leakage_found'] = detect_prompt_leakage(content, verbose)
    
    return content, report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Remediate AI-generated content issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ai_content_remediator.py input.md output.md
  python3 ai_content_remediator.py input.md --diff
  python3 ai_content_remediator.py input.md --in-place
  python3 ai_content_remediator.py input.md --verbose
        """
    )
    parser.add_argument('input_file', help='Input markdown file')
    parser.add_argument('output_file', nargs='?', default=None, 
                        help='Output file (default: show diff)')
    parser.add_argument('--diff', action='store_true', 
                        help='Show diff instead of saving')
    parser.add_argument('--in-place', action='store_true',
                        help='Overwrite input file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Check without making changes')
    parser.add_argument('--no-spacing', action='store_true',
                        help='Skip markdown spacing normalization')
    parser.add_argument('--no-comments', action='store_true',
                        help='Skip HTML comment cleaning')
    parser.add_argument('--remove-comments', action='store_true',
                        help='Remove HTML comments entirely (instead of cleaning)')
    
    args = parser.parse_args()
    
    # Validate input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    if args.verbose:
        print(f"Processing: {input_path}")
        print()
    
    # Read content
    original_content = read_file(str(input_path))
    
    # Apply remediation
    remove_comments = args.remove_comments
    
    remediated_content, report = remediate_content(
        original_content, 
        verbose=args.verbose,
        remove_comments=remove_comments
    )
    
    # If --no-spacing, revert spacing normalization
    if args.no_spacing:
        # Re-run without spacing normalization
        if remove_comments:
            content_no_spacing = remove_html_comments(original_content)
        else:
            content_no_spacing, _ = clean_html_comments(original_content, False)
        remediated_content, report_no_spacing = remediate_content(
            content_no_spacing, verbose=args.verbose, remove_comments=remove_comments
        )
        report_no_spacing['spacing_normalized'] = 0
        report = report_no_spacing
    
    # If --no-comments, revert comment cleaning
    if args.no_comments and not remove_comments:
        # Re-run without comment cleaning
        content_no_comments, _ = normalize_markdown_spacing(original_content, False)
        remediated_content, report_no_comments = remediate_content(
            content_no_comments, verbose=args.verbose, remove_comments=False
        )
        report_no_comments['html_comments_cleaned'] = 0
        report = report_no_comments
    
    # Determine output
    if args.diff or (args.output_file is None and not args.in_place):
        # Show diff
        diff = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            remediated_content.splitlines(keepends=True),
            fromfile=str(input_path),
            tofile='remediated',
        )
        print('\n'.join(diff))
        
    elif args.in_place:
        # Overwrite input file
        if not args.dry_run:
            write_file(str(input_path), remediated_content)
            print(f"Overwritten: {input_path}")
        else:
            print(f"[Dry run] Would overwrite: {input_path}")
        
    else:
        # Write to output file
        output_path = Path(args.output_file)
        if not args.dry_run:
            write_file(str(output_path), remediated_content)
            print(f"Saved: {output_path}")
        else:
            print(f"[Dry run] Would save: {output_path}")
    
    # Print report
    print("\n" + "="*60)
    print("REMEDIATION REPORT")
    print("="*60)
    print(f"  HTML comments cleaned: {report['html_comments_cleaned']}")
    print(f"  Markdown spacing normalized: {report['spacing_normalized']}")
    print(f"  Internal notes preserved: {report['internal_notes_preserved']}")
    
    if report['token_repetitions_found']:
        print(f"\n  Token repetitions found ({len(report['token_repetitions_found'])}):")
        for seq, positions in report['token_repetitions_found'][:5]:  # Top 5
            print(f"    - '{seq}' (appears {len(positions)} times)")
    
    if report['prompt_leakage_found']:
        print(f"\n  Prompt leakage patterns found ({len(report['prompt_leakage_found'])}):")
        for text, pos, pattern_name in report['prompt_leakage_found'][:5]:
            print(f"    - {pattern_name}: '{text}'")
    
    print("="*60)
    
    # Return exit code: 0 if no issues found, 1 if issues remain
    issues_remaining = (
        len(report['token_repetitions_found']) > 0 or
        len(report['prompt_leakage_found']) > 0
    )
    sys.exit(1 if issues_remaining else 0)


if __name__ == '__main__':
    main()
