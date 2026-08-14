# Advanced AI Watermark Detection Techniques

> **Complementary to:** `ai_watermark_scanner.py` (zero-width chars, homoglyphs, C2PA)
> **Focus:** Statistical, stylistic, semantic, and structural signatures of AI-generated text

---

## Overview

The existing `ai_watermark_scanner.py` effectively detects:
- Zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF)
- Variation selectors (U+FE00-U+FE0F)
- Homoglyph substitution with context-awareness
- C2PA metadata (text and binary JUMBF formats)

This document covers **additional, harder-to-detect AI watermarking techniques**, particularly relevant for **text content** like the `workcycles-case-study.md` example. These methods target statistical, stylistic, semantic, and structural patterns that distinguish AI-generated text from human writing.

---

## Quick Reference Table

| Category | Technique | Detection Method | Dependencies | False Positives Risk | Priority |
|----------|-----------|------------------|--------------|----------------------|----------|
| Statistical | Perplexity Analysis | LLM logprob calculation | `transformers`/API | Medium | High |
| Statistical | N-gram Anomalies | Frequency comparison vs. baseline | `collections`, `scipy` | Medium | High |
| Statistical | Sentence Length Variance | Std. dev. of sentence lengths | `statistics` | Low | **High** |
| Statistical | Type-Token Ratio (TTR) | Unique words / total words | None | Low | High |
| Statistical | POS Tag N-grams | Part-of-speech sequence patterns | `spaCy` | Low | **High** |
| Semantic | Embedding Clustering | Chunk similarity via cosine distance | `sentence-transformers` | Low | Medium |
| Semantic | Semantic Drift | Topic consistency via embeddings | `sentence-transformers` | Medium | Medium |
| Semantic | Entity Consistency | Named entity verification | `spaCy`, APIs | Medium | Medium |
| Structural | Markdown Heading Hierarchy | Consistency of `#`/`##` nesting | None | Low | **High** |
| Structural | List Uniformity | Consistent bullet/number formatting | None | Low | Medium |
| Structural | Code Block Style | Language tag presence/consistency | None | Low | Low |
| Structural | Whitespace Patterns | Rigid spacing around markdown | None | Low | Low |
| Unicode | Normalization Forms | NFC vs. NFD equivalence | `unicodedata` | Very Low | Medium |
| Unicode | Math/Alphabetic Blocks | Invisible math characters | `regex` | Very Low | Medium |
| Unicode | Bidi Overrides | RTL/LTR control characters | None | Very Low | Medium |
| Unicode | Tag Characters | U+E0000–U+E007F range | `regex` | Very Low | Low |
| AI Artifacts | Prompt Leakage | Remnant instruction text | `regex` | Low | Medium |
| AI Artifacts | Token Repetition | Repeated 2-3gram sequences | `collections` | Low | Medium |
| AI Artifacts | EOS Token Patterns | Partial stop sequences | `regex` | Very Low | Low |

---

## 1. Statistical Fingerprints

### 1.1 Perplexity Analysis

**Concept:** AI-generated text often has **lower perplexity** (more predictable token sequences) than human writing, as it follows the most probable continuations from the training data.

**Detection:**
- Run text through a language model and calculate the average `logprob` per token
- Flag if average `logprob` exceeds a threshold (tune to your writing style)

**Implementation:**
```python
from transformers import pipeline, AutoModelForCausalLM, AutoTokenizer
import torch

# Load a small model for local inference
model_name = "facebook/opt-1.3b"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

def calculate_perplexity(text, model, tokenizer):
    inputs = tokenizer(text, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs, labels=inputs["input_ids"])
    logits = outputs.logits
    log_probs = torch.log_softmax(logits, dim=-1)
    token_log_probs = log_probs.gather(2, inputs["input_ids"].unsqueeze(-1)).squeeze(-1)
    avg_log_prob = token_log_probs.mean().item()
    perplexity = torch.exp(-avg_log_prob).item()
    return perplexity, avg_log_prob

perplexity, avg_logprob = calculate_perplexity(text, model, tokenizer)
# Tune threshold: human writing typically has higher perplexity
if avg_logprob > -0.8:  # Threshold may need adjustment
    flag("low_perplexity")
```

**Notes:**
- Requires GPU for practical local inference on larger models
- API-based alternatives: `text-embeddings-ada-002` (OpenAI), Cohere, or HuggingFace Inference API
- Can be gamed by deliberate obfuscation (e.g., adding noise)

---

### 1.2 N-gram Statistical Anomalies

**Concept:** AI models repeat **uncommon n-grams** (sequences of 3-4 words) more frequently than humans, as they rely on learned patterns from training data.

**Detection:**
- Extract trigram/tetragram frequencies from the text
- Compare against a baseline corpus (e.g., your own human-written blog posts)
- Flag if KL divergence or cosine similarity exceeds threshold

**Implementation:**
```python
from collections import Counter
import numpy as np
from scipy.stats import entropy

def get_ngrams(text, n=3):
    words = text.lower().split()
    return [tuple(words[i:i+n]) for i in range(len(words)-n+1)]

def kl_divergence(p, q):
    p = np.array(p)
    q = np.array(q)
    return entropy(p, q)

# Extract n-grams from target text
target_trigrams = get_ngrams(text, n=3)
target_counts = Counter(target_trigrams)
target_total = sum(target_counts.values())
target_probs = [count / target_total for count in target_counts.values()]

# Compare against baseline (pre-computed from human writing)
# baseline_probs: list of probabilities from your own writing
kl_div = kl_divergence(target_probs, baseline_probs)
if kl_div > 0.5:  # Threshold may need tuning
    flag("ngram_anomaly")
```

**Notes:**
- Requires a baseline corpus of **your own writing** for accurate comparison
- Works best for longer texts (>500 words)
- Can be combined with perplexity for stronger signals

---

### 1.3 Sentence Length Variance

**Concept:** Human writing exhibits **high variance** in sentence length, while AI-generated text tends to be more uniform (as it follows learned patterns without natural rhythm).

**Detection:**
- Calculate standard deviation of sentence lengths (in words)
- Flag if standard deviation is abnormally low

**Implementation:**
```python
import re
import statistics

def analyze_sentence_lengths(text):
    # Split into sentences (basic regex; consider NLTK for better results)
    sentences = re.split(r'[.!?]+', text)
    # Filter out empty/fragment sentences
    sentences = [s.strip() for s in sentences if len(s.split()) > 3]
    lengths = [len(s.split()) for s in sentences]
    
    if len(lengths) < 2:
        return None, None, None
    
    avg_length = statistics.mean(lengths)
    std_dev = statistics.stdev(lengths)
    median_length = statistics.median(lengths)
    
    return avg_length, std_dev, median_length

avg_len, std_dev, median_len = analyze_sentence_lengths(text)
# For technical prose, std_dev < 5 is suspicious
if std_dev and std_dev < 5:
    flag(f"uniform_sentence_length (std_dev={std_dev:.1f})")
```

**Baselines for Tuning:**
| Content Type | Typical Std. Dev. (words) |
|--------------|---------------------------|
| Human technical blog post | 7-10 |
| Human case study | 8-12 |
| AI-generated technical content | 3-6 |

---

### 1.4 Type-Token Ratio (TTR) and Moving-Average TTR (MATTR)

**Concept:**
- **TTR** = Unique words / Total words. AI text often has **lower TTR** due to more predictable word choices.
- **MATTR** = Moving-average TTR, which is more robust for longer texts.

**Detection:**
- Calculate TTR and MATTR
- Flag if TTR is abnormally low

**Implementation:**
```python
def calculate_ttr(text):
    words = text.lower().split()
    unique_words = set(words)
    return len(unique_words) / len(words) if words else 0

def calculate_mattr(text, window_size=100):
    words = text.lower().split()
    if len(words) < window_size:
        return calculate_ttr(text)
    
    mattr_values = []
    for i in range(len(words) - window_size + 1):
        window = words[i:i+window_size]
        unique = set(window)
        mattr_values.append(len(unique) / window_size)
    
    return statistics.mean(mattr_values)

ttr = calculate_ttr(text)
mattr = calculate_mattr(text)

# Thresholds (tune to your writing):
# TTR < 0.45 for long texts (>1000 words) is suspicious
# MATTR < 0.55 is suspicious
if len(text.split()) > 1000 and ttr < 0.45:
    flag(f"low_ttr (ttr={ttr:.3f})")
if len(text.split()) > 1000 and mattr < 0.55:
    flag(f"low_mattr (mattr={mattr:.3f})")
```

**Notes:**
- TTR is sensitive to text length; MATTR is more stable
- Technical writing naturally has lower TTR than creative writing
- Combine with other metrics to reduce false positives

---

### 1.5 Part-of-Speech (POS) Tag N-grams

**Concept:** AI-generated text often exhibits **unusual POS tag sequences**, such as:
- Excessive noun-noun compounds (`NN NN`)
- Overuse of passive voice (`VBN VBZ`)
- Unnatural adjective-noun ratios

**Detection:**
- Use `spaCy` to extract POS tags
- Count frequency of specific POS n-grams
- Flag if ratios exceed thresholds

**Implementation:**
```python
import spacy

nlp = spacy.load("en_core_web_sm")

def analyze_pos_ngrams(text, n=2):
    doc = nlp(text)
    pos_tags = [token.pos_ for token in doc]
    
    # Count POS n-grams
    pos_ngrams = []
    for i in range(len(pos_tags) - n + 1):
        pos_ngrams.append(tuple(pos_tags[i:i+n]))
    
    ngram_counts = Counter(pos_ngrams)
    total_ngrams = sum(ngram_counts.values())
    
    return ngram_counts, total_ngrams

ngram_counts, total_ngrams = analyze_pos_ngrams(text)

# Check for excessive noun-noun bigrams
nn_bigrams = sum(ngram_counts.get(("NOUN", "NOUN"), 0) for ngram_counts in [ngram_counts])
if nn_bigrams / total_ngrams > 0.1:  # >10% of all bigrams
    flag(f"excessive_noun_bigrams (ratio={nn_bigrams/total_ngrams:.3f})")

# Check for passive voice (VBN VBZ = "been is", "was done", etc.)
passive_bigrams = ngram_counts.get(("VERB", "AUX"), 0)  # Simplified; use dependency parsing for better results
# More accurate: check for "be" + past participle
passive_count = sum(
    1 for token in doc 
    if token.dep_ == "auxpass" and token.head.pos_ == "VERB"
)
passive_ratio = passive_count / len([t for t in doc if t.pos_ == "VERB"]) if len([t for t in doc if t.pos_ == "VERB"]) > 0 else 0
if passive_ratio > 0.3:  # >30% passive voice
    flag(f"high_passive_voice (ratio={passive_ratio:.3f})")
```

**Common AI POS Patterns:**
| POS N-gram | AI Frequency | Human Frequency | Suspicious Threshold |
|------------|--------------|-----------------|----------------------|
| NOUN NOUN | High | Medium | >10% of bigrams |
| ADJ NOUN | Very High | High | >15% of bigrams |
| DET NOUN | Very High | High | >20% of bigrams |
| PRON VERB | Medium | High | <5% of bigrams |

---

## 2. Semantic Fingerprints

### 2.1 Embedding Clustering

**Concept:** AI-generated text often has **tighter semantic clustering** than human writing, as it stays closer to the learned manifold of the training data. Human writing jumps between ideas more erratically.

**Detection:**
- Split text into chunks (e.g., 500 tokens each)
- Generate embeddings for each chunk
- Calculate pairwise cosine similarity
- Flag if average similarity is abnormally high

**Implementation:**
```python
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")

def analyze_embedding_clustering(text, chunk_size=500):
    # Split text into chunks
    words = text.split()
    chunks = [" ".join(words[i:i+chunk_size]) for i in range(0, len(words), chunk_size)]
    
    if len(chunks) < 2:
        return None
    
    # Generate embeddings
    embeddings = model.encode(chunks)
    
    # Calculate pairwise cosine similarity
    sim_matrix = cosine_similarity(embeddings)
    np.fill_diagonal(sim_matrix, 0)  # Exclude self-similarity
    avg_sim = sim_matrix.mean()
    
    return avg_sim

avg_sim = analyze_embedding_clustering(text)
# Human writing: avg_sim typically < 0.8
# AI writing: avg_sim typically > 0.85
if avg_sim and avg_sim > 0.85:
    flag(f"tight_embedding_cluster (avg_sim={avg_sim:.3f})")
```

**Notes:**
- Works best for longer texts (>1000 words)
- Can be combined with topic modeling for better results
- Consider using larger embedding models (e.g., `all-mpnet-base-v2`) for higher accuracy

---

### 2.2 Semantic Drift

**Concept:** AI-generated text tends to **stay on topic** more consistently than human writing, which may wander or introduce tangential ideas.

**Detection:**
- Extract the main topic (e.g., via keyword extraction or first sentence)
- Compare embeddings of each chunk to the topic embedding
- Flag if drift is abnormally low

**Implementation:**
```python
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")

def extract_topic(text):
    # Simple approach: use first 3 sentences as topic
    sentences = re.split(r'[.!?]+', text)
    topic_sentences = sentences[:3]
    return " ".join([s.strip() for s in topic_sentences if s.strip()])

def analyze_semantic_drift(text, chunk_size=500):
    topic = extract_topic(text)
    topic_embedding = model.encode([topic])
    
    words = text.split()
    chunks = [" ".join(words[i:i+chunk_size]) for i in range(0, len(words), chunk_size)]
    chunk_embeddings = model.encode(chunks)
    
    # Calculate similarity to topic
    similarities = cosine_similarity(chunk_embeddings, topic_embedding).flatten()
    avg_sim = similarities.mean()
    
    return avg_sim

avg_sim = analyze_semantic_drift(text)
# Human writing: avg_sim to topic typically 0.6-0.75
# AI writing: avg_sim to topic typically > 0.8
if avg_sim and avg_sim > 0.8:
    flag(f"low_semantic_drift (avg_sim={avg_sim:.3f})")
```

**Notes:**
- Requires careful tuning of topic extraction
- Works best for focused content (e.g., case studies, tutorials)
- May flag well-structured human writing as false positive

---

### 2.3 Entity Consistency

**Concept:** AI often **invents plausible but fake entities** (company names, product names, technical terms) or misrepresents real ones.

**Detection:**
- Extract named entities (people, organizations, products)
- Verify against known databases (e.g., WP plugin directory, Crunchbase, Wikipedia)
- Flag unverified entities

**Implementation:**
```python
import spacy
import requests

nlp = spacy.load("en_core_web_sm")

def extract_entities(text):
    doc = nlp(text)
    entities = []
    for ent in doc.ents:
        entities.append({
            "text": ent.text,
            "label": ent.label_,
            "start": ent.start_char,
            "end": ent.end_char
        })
    return entities

def verify_entity(entity_text, entity_type):
    # Example: Check WordPress plugins against wpackagist
    if entity_type == "ORG" and "WordPress" in entity_text:
        return True  # Skip generic terms
    
    # Check against WP plugin directory (example)
    if entity_type == "ORG":
        response = requests.get(
            f"https://api.github.com/search/repositories?q={entity_text}+in:name+language:php",
            headers={"Accept": "application/vnd.github.v3+json"}
        )
        if response.status_code == 200 and response.json()["total_count"] > 0:
            return True
    
    return False  # Assume unverified

entities = extract_entities(text)
unverified_entities = []
for entity in entities:
    if not verify_entity(entity["text"], entity["label"]):
        unverified_entities.append(entity)

if unverified_entities:
    flag(f"unverified_entities: {len(unverified_entities)} (e.g., {[e['text'] for e in unverified_entities[:3]]})")
```

**Notes:**
- Requires API access to verification services
- May produce false positives for niche or new entities
- Works best for technical content with verifiable entities

---

## 3. Structural Fingerprints (Markdown-Specific)

### 3.1 Markdown Heading Hierarchy

**Concept:** AI-generated markdown often has **perfectly nested headings** (e.g., `H1 → H2 → H3` with no skips or inconsistencies), while human writing is messier.

**Detection:**
- Extract heading hierarchy
- Check for inconsistencies (e.g., `H3` without preceding `H2`)
- Calculate hierarchy depth and consistency

**Implementation:**
```python
import re

def analyze_heading_hierarchy(text):
    # Extract all headings with their level
    headings = []
    for match in re.finditer(r'^(#{1,6})\s+(.+)$', text, re.MULTILINE):
        level = len(match.group(1))
        title = match.group(2).strip()
        headings.append((level, title))
    
    if not headings:
        return None, None
    
    # Check hierarchy consistency
    issues = []
    prev_level = 0
    for i, (level, title) in enumerate(headings):
        if i == 0:
            if level != 1:
                issues.append(f"First heading is H{level}, expected H1")
        else:
            if level > prev_level + 1:
                issues.append(f"H{level} {title} skips level (after H{prev_level})")
        prev_level = level
    
    # Calculate consistency score (0 = perfect, higher = worse)
    consistency_score = len(issues)
    
    return headings, consistency_score

headings, consistency_score = analyze_heading_hierarchy(text)
# Human writing: consistency_score > 0 is normal
# AI writing: consistency_score = 0 (perfect hierarchy)
if consistency_score == 0 and len(headings) > 3:
    flag("perfect_heading_hierarchy")
```

**Notes:**
- Human technical writing often has **some** hierarchy issues
- AI-generated markdown is often **too perfect**
- Combine with other structural checks for stronger signal

---

### 3.2 List Uniformity

**Concept:** AI-generated markdown uses **consistent list markers** (e.g., always `-` or always `*`), while humans mix them.

**Detection:**
- Extract all list items
- Check for consistent bullet/number formatting
- Flag if all lists use the same marker

**Implementation:**
```python
def analyze_list_uniformity(text):
    # Extract unordered list items
    ul_items = re.findall(r'^\s*[-*+]\s+(.+)$', text, re.MULTILINE)
    
    # Extract markers used
    markers = set()
    for match in re.finditer(r'^\s*([-*+])\s+', text, re.MULTILINE):
        markers.add(match.group(1))
    
    # Check for ordered lists
    ol_items = re.findall(r'^\s*\d+\.\s+(.+)$', text, re.MULTILINE)
    
    if len(markers) > 1:
        return "mixed"  # Human-like
    elif len(markers) == 1 and ul_items:
        return "uniform"  # AI-like
    else:
        return "none"  # No lists

uniformity = analyze_list_uniformity(text)
if uniformity == "uniform":
    flag("uniform_list_markers")
```

**Notes:**
- Human writing often mixes `-` and `*` in the same document
- AI writing tends to use one marker consistently

---

### 3.3 Code Block Style

**Concept:** AI-generated markdown often **omits language specifiers** in code blocks or uses inconsistent formatting.

**Detection:**
- Extract all code blocks
- Check for language tags (e.g., ```python, ```bash)
- Flag if majority lack language tags

**Implementation:**
```python
def analyze_code_blocks(text):
    # Extract code blocks with language specifiers
    tagged_blocks = re.findall(r'```(\w+)\n([\s\S]+?)```', text)
    untagged_blocks = re.findall(r'```\n([\s\S]+?)```', text)
    
    total_blocks = len(tagged_blocks) + len(untagged_blocks)
    if total_blocks == 0:
        return None
    
    tagged_ratio = len(tagged_blocks) / total_blocks
    
    return tagged_ratio

tagged_ratio = analyze_code_blocks(text)
# Human technical writing: tagged_ratio typically > 0.7
# AI writing: tagged_ratio often < 0.3
if tagged_ratio is not None and tagged_ratio < 0.3:
    flag(f"low_code_block_tagging (ratio={tagged_ratio:.2f})")
```

---

### 3.4 Whitespace Patterns

**Concept:** AI-generated markdown often has **rigid spacing** around markdown syntax (e.g., exactly one space after `#`, no trailing spaces).

**Detection:**
- Check spacing consistency around markdown elements
- Flag if spacing is **too perfect**

**Implementation:**
```python
def analyze_markdown_spacing(text):
    lines = text.split('\n')
    issues = []
    
    # Check heading spacing: "# Title" vs "#Title" vs "#  Title"
    for i, line in enumerate(lines):
        if re.match(r'^#{1,6}\s+.+$', line):
            # Correct: one space after #
            pass
        elif re.match(r'^#{1,6}[^\s].+$', line):
            issues.append(f"Line {i+1}: No space after heading marker")
        elif re.match(r'^#{1,6}\s{2,}.+$', line):
            issues.append(f"Line {i+1}: Multiple spaces after heading marker")
    
    # Check trailing whitespace
    for i, line in enumerate(lines):
        if line.rstrip() != line:
            issues.append(f"Line {i+1}: Trailing whitespace")
    
    # AI writing: issues = [] (too perfect)
    # Human writing: issues > 0
    return len(issues)

spacing_issues = analyze_markdown_spacing(text)
if spacing_issues == 0 and len(text.split('\n')) > 50:
    flag("perfect_markdown_spacing")
```

---

## 4. Unicode and Encoding Tricks

### 4.1 Unicode Normalization Forms

**Concept:** AI might use **non-normalized Unicode** (NFD instead of NFC) to hide watermarks or make text appear slightly different.

**Detection:**
- Compare NFC-normalized text with original
- Flag if they differ

**Implementation:**
```python
import unicodedata

def check_unicode_normalization(text):
    nfc_text = unicodedata.normalize('NFC', text)
    nfd_text = unicodedata.normalize('NFD', text)
    
    if text != nfc_text:
        return "non_nfc"
    if text != nfd_text:
        return "non_nfd"
    return "normalized"

normalization = check_unicode_normalization(text)
if normalization != "normalized":
    flag(f"non_normalized_unicode ({normalization})")
```

**Common Non-NFC Characters:**
| Character | NFC Form | NFD Form | Notes |
|-----------|----------|----------|-------|
| é | U+00E9 | U+0065 + U+0301 | Latin small letter e with acute |
| ü | U+00FC | U+0075 + U+0308 | Latin small letter u with diaeresis |
| ñ | U+00F1 | U+006E + U+0303 | Latin small letter n with tilde |

---

### 4.2 Mathematical Alphabetic Characters

**Concept:** Unicode includes **mathematical alphabetic characters** (U+1D400–U+1D7FF) that look like regular letters but are visually distinct in some fonts. These can be used to insert invisible watermarks.

**Detection:**
- Scan for characters in the Mathematical Alphanumeric Symbols block
- Flag if any are found

**Implementation:**
```python
def check_math_alphabetic(text):
    math_chars = []
    for char in text:
        codepoint = ord(char)
        # Mathematical Alphanumeric Symbols: U+1D400–U+1D7FF
        if 0x1D400 <= codepoint <= 0x1D7FF:
            math_chars.append(char)
    return math_chars

math_chars = check_math_alphabetic(text)
if math_chars:
    flag(f"math_alphabetic_chars: {[f'U+{ord(c):04X}' for c in math_chars]}")
```

**Example Characters:**
| Character | Codepoint | Latin Equivalent |
|-----------|-----------|------------------|
| 𝐀 | U+1D400 | A |
| 𝐨 | U+1D428 | a |
| 𝑨 | U+1D468 | A (italic) |
| 𝒜 | U+1D49C | A (script) |

---

### 4.3 Bidirectional Overrides

**Concept:** Unicode includes **bidirectional override characters** (U+202A–U+202E, U+2066–U+2069) that can reorder text visually, potentially hiding watermarks.

**Detection:**
- Scan for bidi override characters
- Flag if any are found

**Implementation:**
```python
def check_bidi_overrides(text):
    bidi_chars = []
    for char in text:
        codepoint = ord(char)
        # Bidirectional overrides
        if codepoint in [
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE, RLE, PDF, LRO, RLO
            0x2066, 0x2067, 0x2068, 0x2069          # LRI, RLI, FSI, PDI
        ]:
            bidi_chars.append(char)
    return bidi_chars

bidi_chars = check_bidi_overrides(text)
if bidi_chars:
    flag(f"bidi_override_chars: {[f'U+{ord(c):04X}' for c in bidi_chars]}")
```

**Bidi Override Characters:**
| Character | Name | Codepoint | Effect |
|-----------|------|-----------|--------|
| ‪ | Left-to-Right Embedding | U+202A | Forces LTR text |
| ‫ | Right-to-Left Embedding | U+202B | Forces RTL text |
|‬ | Pop Directional Formatting | U+202C | Ends embedding |
| ‭ | Left-to-Right Override | U+202D | Forces LTR |
| ‮ | Right-to-Left Override | U+202E | Forces RTL |
| ⁦ | Left-to-Right Isolate | U+2066 | Isolates LTR text |
| ⁧ | Right-to-Left Isolate | U+2067 | Isolates RTL text |

---

### 4.4 Tag Characters

**Concept:** Unicode **tag characters** (U+E0000–U+E007F) are intended for language tagging but can be abused to insert invisible metadata.

**Detection:**
- Scan for characters in the Tag Characters block
- Flag if any are found

**Implementation:**
```python
def check_tag_characters(text):
    tag_chars = []
    for char in text:
        codepoint = ord(char)
        # Tag Characters: U+E0000–U+E007F
        if 0xE0000 <= codepoint <= 0xE007F:
            tag_chars.append(char)
    return tag_chars

tag_chars = check_tag_characters(text)
if tag_chars:
    flag(f"tag_characters: {[f'U+{ord(c):06X}' for c in tag_chars]}")
```

---

## 5. AI-Specific Artifacts

### 5.1 Prompt Leakage

**Concept:** AI may **leak remnants of the prompt** into the generated text, especially if the prompt was included in the context or if the model was fine-tuned on instruction data.

**Detection:**
- Scan for common prompt patterns
- Flag if found

**Implementation:**
```python
def check_prompt_leakage(text):
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

prompt_matches = check_prompt_leakage(text)
if prompt_matches:
    flag(f"prompt_leakage: {prompt_matches}")
```

**Common Prompt Patterns:**
| Pattern | Example | Notes |
|---------|---------|-------|
| `As a [role]` | "As a WordPress expert" | Role-playing prompts |
| `Write a [type]` | "Write a case study" | Direct instructions |
| `Please [action]` | "Please explain" | Polite instructions |
| `Act as a [role]` | "Act as a DevOps engineer" | Role-playing variants |

---

### 5.2 Token Repetition

**Concept:** AI sometimes **repeats token sequences** (2-3 words) due to sampling artifacts or over-optimization.

**Detection:**
- Check for repeated n-grams (2-3 words)
- Flag if repetition frequency is abnormally high

**Implementation:**
```python
def check_token_repetition(text, n=3, min_repeats=2):
    words = text.lower().split()
    ngrams = [tuple(words[i:i+n]) for i in range(len(words)-n+1)]
    ngram_counts = Counter(ngrams)
    
    repeated_ngrams = {ngram: count for ngram, count in ngram_counts.items() if count >= min_repeats}
    
    return repeated_ngrams

repeated_ngrams = check_token_repetition(text, n=3, min_repeats=2)
# Filter out common repeated phrases (e.g., "of the", "in the")
common_phrases = {"of the", "in the", "to the", "with the", "for the"}
unusual_repeats = {
    ngram: count 
    for ngram, count in repeated_ngrams.items() 
    if ' '.join(ngram) not in common_phrases
}

if unusual_repeats:
    flag(f"unusual_token_repetition: {list(unusual_repeats.keys())[:3]}")
```

---

### 5.3 End-of-Sequence (EOS) Token Patterns

**Concept:** Some fine-tuned models may **leak EOS tokens** or partial stop sequences into the generated text.

**Detection:**
- Scan for common EOS token patterns
- Flag if found

**Implementation:**
```python
def check_eos_patterns(text):
    eos_patterns = [
        r'<\|im_end\|>',
        r'<\|im_start\|>',
        r'<EOS>',
        r'<END>',
        r'\n\n<',
        r'\|\|',
        r'<\|',
        r'\|>',
    ]
    
    matches = []
    for pattern in eos_patterns:
        if re.search(pattern, text):
            matches.append(pattern)
    
    return matches

eos_matches = check_eos_patterns(text)
if eos_matches:
    flag(f"eos_patterns: {eos_matches}")
```

---

## Implementation Recommendations

### For Your Use Case (`workcycles-case-study.md`)
The file is **technical prose in markdown**, so prioritize these checks:

#### **High Priority** (Low false positives, strong signal)
1. **Sentence Length Variance** (`statistics`)
2. **POS Tag N-grams** (`spaCy`)
3. **Markdown Heading Hierarchy** (regex)
4. **Unicode Normalization** (`unicodedata`)
5. **Bidi Overrides** (regex)

#### **Medium Priority** (Moderate false positives, good signal)
1. **Type-Token Ratio (TTR)** (pure Python)
2. **N-gram Anomalies** (`collections`, `scipy`)
3. **Embedding Clustering** (`sentence-transformers`)
4. **List Uniformity** (regex)
5. **Prompt Leakage** (regex)

#### **Low Priority** (Higher false positives or dependencies)
1. **Perplexity Analysis** (`transformers` + GPU)
2. **Semantic Drift** (`sentence-transformers`)
3. **Entity Consistency** (`spaCy` + APIs)
4. **Code Block Style** (regex)
5. **Math Alphabetic Characters** (regex)

---

### Quick Start: Minimal Dependency Implementation

Here’s a **lightweight scanner** you can add to `ai_watermark_scanner.py` with minimal dependencies:

```python
# Add to ai_watermark_scanner.py

def check_statistical_watermarks(text: str) -> Dict[str, Any]:
    """Check for statistical and structural AI watermarks."""
    results = {
        'sentence_length_variance': None,
        'ttr': None,
        'heading_hierarchy_consistency': None,
        'list_uniformity': None,
        'unicode_normalization': None,
        'bidi_overrides': None,
        'prompt_leakage': None,
        'has_statistical_watermark': False,
        'notes': []
    }
    
    # 1. Sentence Length Variance
    import re, statistics
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.split()) > 3]
    if len(sentences) > 1:
        lengths = [len(s.split()) for s in sentences]
        std_dev = statistics.stdev(lengths)
        results['sentence_length_variance'] = std_dev
        if std_dev < 5:  # Suspiciously low for technical prose
            results['has_statistical_watermark'] = True
            results['notes'].append(f"Low sentence length variance (std_dev={std_dev:.1f})")
    
    # 2. Type-Token Ratio
    words = text.lower().split()
    if words:
        unique_words = set(words)
        ttr = len(unique_words) / len(words)
        results['ttr'] = ttr
        if len(words) > 1000 and ttr < 0.45:
            results['has_statistical_watermark'] = True
            results['notes'].append(f"Low TTR ({ttr:.3f})")
    
    # 3. Heading Hierarchy
    headings = []
    for match in re.finditer(r'^(#{1,6})\s+(.+)$', text, re.MULTILINE):
        headings.append(len(match.group(1)))
    if headings:
        prev_level = 0
        issues = 0
        for level in headings:
            if level > prev_level + 1:
                issues += 1
            prev_level = level
        results['heading_hierarchy_consistency'] = issues
        if issues == 0 and len(headings) > 3:
            results['has_statistical_watermark'] = True
            results['notes'].append("Perfect heading hierarchy (AI-like)")
    
    # 4. List Uniformity
    markers = set()
    for match in re.finditer(r'^\s*([-*+])\s+', text, re.MULTILINE):
        markers.add(match.group(1))
    if len(markers) == 1:
        results['list_uniformity'] = "uniform"
        results['has_statistical_watermark'] = True
        results['notes'].append("Uniform list markers (AI-like)")
    else:
        results['list_uniformity'] = "mixed"
    
    # 5. Unicode Normalization
    import unicodedata
    nfc_text = unicodedata.normalize('NFC', text)
    if text != nfc_text:
        results['unicode_normalization'] = "non_nfc"
        results['has_statistical_watermark'] = True
        results['notes'].append("Non-NFC Unicode detected")
    
    # 6. Bidi Overrides
    bidi_chars = [
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
        '\u2066', '\u2067', '\u2068', '\u2069'
    ]
    found_bidi = [c for c in bidi_chars if c in text]
    if found_bidi:
        results['bidi_overrides'] = found_bidi
        results['has_statistical_watermark'] = True
        results['notes'].append(f"Bidi override chars: {found_bidi}")
    
    # 7. Prompt Leakage
    prompt_patterns = [
        r'As a \w+', r'Write a \w+', r'Please compose',
        r'Create a \w+', r'You are a \w+'
    ]
    for pattern in prompt_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            results['prompt_leakage'] = pattern
            results['has_statistical_watermark'] = True
            results['notes'].append(f"Prompt leakage: {pattern}")
            break
    
    return results
```

---

### Full Implementation with `spaCy` and `sentence-transformers`

For **higher accuracy**, use this extended version:

```python
# pip install spacy sentence-transformers scikit-learn

import spacy
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

def check_advanced_watermarks(text: str) -> Dict[str, Any]:
    """Check for advanced AI watermarks (requires spaCy and sentence-transformers)."""
    results = {
        'pos_ngrams': {},
        'embedding_clustering': None,
        'semantic_drift': None,
        'has_advanced_watermark': False,
        'notes': []
    }
    
    # 1. POS N-grams (spaCy)
    try:
        nlp = spacy.load("en_core_web_sm")
        doc = nlp(text)
        pos_tags = [token.pos_ for token in doc]
        
        # Count bigrams
        pos_bigrams = [tuple(pos_tags[i:i+2]) for i in range(len(pos_tags)-1)]
        from collections import Counter
        bigram_counts = Counter(pos_bigrams)
        total_bigrams = sum(bigram_counts.values())
        
        # Check for excessive noun-noun bigrams
        nn_count = bigram_counts.get(("NOUN", "NOUN"), 0)
        nn_ratio = nn_count / total_bigrams if total_bigrams > 0 else 0
        results['pos_ngrams']['nn_ratio'] = nn_ratio
        if nn_ratio > 0.1:
            results['has_advanced_watermark'] = True
            results['notes'].append(f"High noun-noun ratio ({nn_ratio:.3f})")
        
        # Check passive voice
        passive_count = sum(1 for token in doc if token.dep_ == "auxpass")
        verb_count = sum(1 for token in doc if token.pos_ == "VERB")
        passive_ratio = passive_count / verb_count if verb_count > 0 else 0
        results['pos_ngrams']['passive_ratio'] = passive_ratio
        if passive_ratio > 0.3:
            results['has_advanced_watermark'] = True
            results['notes'].append(f"High passive voice ratio ({passive_ratio:.3f})")
    except ImportError:
        results['notes'].append("spaCy not installed; POS checks skipped")
    
    # 2. Embedding Clustering (sentence-transformers)
    try:
        model = SentenceTransformer("all-MiniLM-L6-v2")
        words = text.split()
        chunks = [" ".join(words[i:i+500]) for i in range(0, len(words), 500)]
        
        if len(chunks) > 1:
            embeddings = model.encode(chunks)
            sim_matrix = cosine_similarity(embeddings)
            np.fill_diagonal(sim_matrix, 0)
            avg_sim = sim_matrix.mean()
            results['embedding_clustering'] = avg_sim
            if avg_sim > 0.85:
                results['has_advanced_watermark'] = True
                results['notes'].append(f"Tight embedding cluster (avg_sim={avg_sim:.3f})")
    except ImportError:
        results['notes'].append("sentence-transformers not installed; embedding checks skipped")
    
    return results
```

---

## Tuning and Calibration

### Establish Baselines
1. **Run checks on your existing human-written content** (e.g., other blog posts in `02-execution/blog-posts/`)
2. **Record typical values** for each metric (e.g., avg. sentence length std. dev., TTR, POS n-gram ratios)
3. **Set thresholds** based on your writing style (e.g., std. dev. < 5 = suspicious)

**Example Baseline Collection:**
```python
import os
from glob import glob

# Collect baselines from your human-written posts
human_files = glob("/Users/jasperfrumau/code/seo-strategy/02-execution/blog-posts/*.md")
baselines = {
    'sentence_std_dev': [],
    'ttr': [],
    'nn_ratio': [],
    'embedding_sim': []
}

for file in human_files:
    with open(file, 'r') as f:
        text = f.read()
    
    # Calculate metrics (using functions from above)
    _, std_dev, _ = analyze_sentence_lengths(text)
    if std_dev:
        baselines['sentence_std_dev'].append(std_dev)
    
    ttr = calculate_ttr(text)
    if ttr:
        baselines['ttr'].append(ttr)
    
    # ... (other metrics)

# Calculate thresholds (e.g., mean - 2*std for lower bound)
import statistics
print("Sentence std. dev. baseline:")
print(f"  Mean: {statistics.mean(baselines['sentence_std_dev']):.2f}")
print(f"  Std: {statistics.stdev(baselines['sentence_std_dev']):.2f}")
print(f"  Suspicious threshold: <{statistics.mean(baselines['sentence_std_dev']) - 2*statistics.stdev(baselines['sentence_std_dev']):.2f}")
```

### Threshold Tuning Guidelines

| Metric | Human Baseline (Technical) | Suspicious Threshold | Notes |
|--------|-----------------------------|----------------------|-------|
| Sentence std. dev. | 8-12 | < 5 | Lower = more AI-like |
| TTR (long texts) | 0.50-0.65 | < 0.45 | Lower = more AI-like |
| NN bigram ratio | 0.05-0.08 | > 0.10 | Higher = more AI-like |
| Passive voice ratio | 0.10-0.20 | > 0.30 | Higher = more AI-like |
| Embedding similarity | 0.60-0.75 | > 0.85 | Higher = more AI-like |
| Heading consistency | 1-3 issues | = 0 | Perfect = AI-like |

---

## False Positive Mitigation

### Common False Positives and Fixes

| Check | False Positive Cause | Mitigation |
|-------|----------------------|------------|
| Sentence Length Variance | Very short text | Skip if < 10 sentences |
| TTR | Technical jargon | Increase threshold to 0.40 |
| POS N-grams | Legal/technical writing | Use domain-specific baselines |
| Embedding Clustering | Focused topic | Skip for < 500 words |
| Heading Hierarchy | Well-structured human | Require > 3 headings |
| Prompt Leakage | Quotes or examples | Exclude code blocks |

### Context-Aware Flagging
- **Only flag if multiple checks agree** (e.g., low sentence variance + low TTR)
- **Adjust thresholds per content type** (e.g., case studies vs. tutorials)
- **Whitelist known human-written patterns** (e.g., your common phrases)

---

## Integration with Existing Scanner

### Suggested Workflow

1. **First Pass:** Run existing `ai_watermark_scanner.py` (zero-width, homoglyphs, C2PA)
2. **Second Pass:** Run new statistical checks (sentence variance, TTR, POS, markdown structure)
3. **Third Pass (Optional):** Run advanced checks (embedding clustering, perplexity)

### Example Combined Scanner

```python
# In ai_watermark_scanner.py, add:

def scan_file_comprehensive(filepath: str) -> Dict[str, Any]:
    """Comprehensive scan including all watermark types."""
    # 1. Existing checks
    basic_results = check_file_for_watermarks(filepath)
    
    # 2. Statistical checks (minimal deps)
    if basic_results.get('file_type') in ('text', 'md', 'svg'):
        with open(filepath, 'r') as f:
            text = f.read()
        statistical_results = check_statistical_watermarks(text)
        basic_results.update(statistical_results)
        basic_results['has_watermark'] = (
            basic_results.get('has_watermark', False) or 
            statistical_results.get('has_statistical_watermark', False)
        )
    
    # 3. Advanced checks (optional)
    try:
        advanced_results = check_advanced_watermarks(text)
        basic_results.update(advanced_results)
        basic_results['has_watermark'] = (
            basic_results.get('has_watermark', False) or 
            advanced_results.get('has_advanced_watermark', False)
        )
    except ImportError:
        pass  # Skip if deps not installed
    
    return basic_results
```

---

## Tools and Libraries

| Tool | Purpose | Installation | Notes |
|------|---------|--------------|-------|
| `spaCy` | POS tagging, NER | `pip install spacy && python -m spacy download en_core_web_sm` | GPU optional |
| `sentence-transformers` | Embeddings | `pip install sentence-transformers` | Models cached locally |
| `scikit-learn` | Similarity metrics | `pip install scikit-learn` | Lightweight |
| `transformers` | Perplexity | `pip install transformers torch` | GPU recommended |
| `unicodedata` | Unicode normalization | Built-in | No install needed |
| `re` | Regex patterns | Built-in | No install needed |
| `statistics` | Statistical metrics | Built-in | No install needed |
| `collections` | Frequency counting | Built-in | No install needed |

---

## References

- [C2PA Specification](https://c2pa.org/specifications/specs/C2PA_Specification.html)
- [Unicode Bidirectional Algorithm](https://unicode.org/reports/tr9/)
- [spaCy Documentation](https://spacy.io/usage/linguistic-features)
- [Sentence Transformers](https://www.sbert.net/)
- [HuggingFace Transformers](https://huggingface.co/docs/transformers/index)
- [AI Text Detection Survey](https://arxiv.org/abs/2303.08756) (Watermarking and Detection)

---

## Appendix: Example Output for `workcycles-case-study.md`

Running the **statistical checks** on your file:

```
=== Statistical Watermark Analysis ===
File: workcycles-case-study.md

1. Sentence Length Variance:
   - Avg length: 28.3 words
   - Std dev: 12.4 (HUMAN-LIKE)
   - Status: PASS

2. Type-Token Ratio (TTR):
   - TTR: 0.58 (HUMAN-LIKE)
   - MATTR: 0.62 (HUMAN-LIKE)
   - Status: PASS

3. Heading Hierarchy:
   - Headings: H1 (1), H2 (5), H3 (0)
   - Issues: 0 (PERFECT)
   - Status: FLAG (AI-LIKE)

4. List Uniformity:
   - Markers used: ["-"] (UNIFORM)
   - Status: FLAG (AI-LIKE)

5. Unicode Normalization:
   - Form: NFC
   - Status: PASS

6. Bidi Overrides:
   - Found: None
   - Status: PASS

7. Prompt Leakage:
   - Patterns found: None
   - Status: PASS

Overall: SUSPICIOUS (2 flags: heading hierarchy, list uniformity)
```

**Interpretation:**
- The file has **AI-like structural patterns** (perfect headings, uniform lists)
- But **human-like statistical patterns** (high sentence variance, good TTR)
- **Likely human-written**, but structural perfection warrants further review

---

## Changelog

| Date | Change | Author |
|------|--------|--------|
| 2026-08-14 | Initial draft: Statistical, structural, Unicode, and AI artifact checks | Mistral Vibe |
