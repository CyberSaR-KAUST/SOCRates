**SOCRates: Rating Hallucinations in LLM-Generated Security Operation Center Reporting**
**SOCRates** is a dedicated research dataset for studying hallucinations in LLM-generated Security Operations Center (SOC) reports. It pairs security analysis outputs with evidence contexts to support the investigation of fabricated indicators, contradictory statements, and unsupported behavioral claims. The dataset provides a shared resource for developing claim extraction, evidence verification, and report correction methods, including approaches that distinguish hallucinations from justified inferences and unresolved assertions.The collection comprises 1,100 cases across two tracks: 1,000 structured security analysis tasks (soc_tasks_1000) and 100 long-form technical triage reports (soc_reports_100). The structured track includes reference outputs and controlled perturbations targeting specific report failures. Each track provides report text, associated evidence contexts, and case metadata as Zstandard-compressed JSONL files (.jsonl.zst), with one JSON object per line.

---

## Dataset at a Glance

| Metric | Value |
|---|---|
| Total cases | 1,100 |
| Track 1 cases (`soc_tasks_1000`) | 1,000 |
| Track 2 cases (`soc_reports_100`) | 100 |
| Track 1 conditions | 10 (clean baseline + 9 controlled perturbations, 100 cases each) |
| File format | `.jsonl.zst` (JSONL + Zstandard compression) |

---

## Collections

| Collection | Records | Files | Compressed Size | Description |
|-----------|---------|--------|----------------|-------------|
| [soc_tasks_1000/](soc_tasks_1000/) | 1,000 cases | 3 files | ~0.66 MB | Structured SOC micro-tasks: 10 condition classes (1 clean baseline + 9 perturbations) × 100 cases each. Includes manifests, structured evidence contexts, and reports (faithful reference text for `CLEAN`, corrupted variants for `P1` to `P9`). |
| [soc_reports_100/](soc_reports_100/) | 100 cases | 3 files | ~0.10 MB | Long-form multi-paragraph incident triage reports with full evidence contexts and manifests. |
| [metadata_001.jsonl.zst](metadata_001.jsonl.zst) | 1 | 1 file | <1 KB | Dataset version, creation date, and collection summary. |

---

## How Collections Relate

```
soc_tasks_1000/ (1,000 micro-task cases)
  │
  ├─ manifest_001.jsonl.zst   ← per-case metadata: case_id, task_type, taxonomy_code,
  │                              perturbation class, error_spans, and hashes
  ├─ contexts_001.jsonl.zst   ← structured evidence bundles (ground-truth analysis,
  │                              decompiled code, MITRE references, and prompt text)
  └─ reports_001.jsonl.zst    ← report text for each case

soc_reports_100/ (100 long-form triage reports)
  │
  ├─ manifest_001.jsonl.zst   ← per-case metadata, including hashes
  ├─ contexts_001.jsonl.zst   ← model-visible evidence contexts
  └─ reports_001.jsonl.zst    ← multi-paragraph report text
```

---

## Prerequisites

```bash
pip install zstandard
```

---


## Loading Data

### Load data

For the published collections, loading a shard into memory is the simplest approach. The largest collection contains 1,000 cases and the compressed
shards are small.

```python
import io
import json
import zstandard as zstd

def load_shard(shard_path):
    """Load an entire shard into a list of dicts."""
    docs = []
    dctx = zstd.ZstdDecompressor()
    with open(shard_path, "rb") as fh:
        with dctx.stream_reader(fh) as reader:
            text_stream = io.TextIOWrapper(reader, encoding="utf-8")
            for line in text_stream:
                line = line.strip()
                if line:
                    docs.append(json.loads(line))
    return docs

# Example: load all 1,000 micro-task manifest entries
entries = load_shard("soc_tasks_1000/manifest_001.jsonl.zst")
print(f"Loaded {len(entries)} manifest entries")
```
### Load into Pandas

```python
import io
import json
import zstandard as zstd
import pandas as pd

def shard_to_dataframe(shard_path, fields=None):
    """Load a shard into a DataFrame, optionally selecting specific fields."""
    rows = []
    dctx = zstd.ZstdDecompressor()
    with open(shard_path, "rb") as fh:
        with dctx.stream_reader(fh) as reader:
            text_stream = io.TextIOWrapper(reader, encoding="utf-8")
            for line in text_stream:
                line = line.strip()
                if line:
                    doc = json.loads(line)
                    if fields:
                        doc = {k: doc.get(k) for k in fields}
                    rows.append(doc)
    return pd.DataFrame(rows)
```

---

## Directory Structure

```
SOCRated/
  README.md                              # This file
  metadata_001.jsonl.zst                 # Dataset version and summary (<1 KB)
  soc_tasks_1000/
    manifest_001.jsonl.zst              # 1,000 case metadata records (~275 KB)
    contexts_001.jsonl.zst              # 1,000 structured evidence bundles (~302 KB)
    reports_001.jsonl.zst               # 1,000 report texts (~82 KB)
  soc_reports_100/
    manifest_001.jsonl.zst              # 100 case metadata records (~29 KB)
    contexts_001.jsonl.zst              # 100 structured evidence bundles (~33 KB)
    reports_001.jsonl.zst               # 100 long-form report texts (~42 KB)
```

---

## Data Format Notes

- **Compression**: Zstandard (level 19). Decompress with the `zstandard` Python library or the `zstd` CLI tool.
- **Format**: One JSON object per line (JSONL), compressed as a single `.jsonl.zst` shard.
- **Contexts**: Each context document contains the model-visible `provided_context`, including the ground-truth reference analysis, decompiled code (from [LCCD](http://hdl.handle.net/10754/709465)), https://www.cyberdeep.io/genspect, MITRE ATT&CK technique descriptions, Windows API documentation snippets, and sample metadata. The ground-truth reference is included for comparison and verification.
- **error_spans**: character spans of injected errors. Empty for clean cases.
- **Truncation**: long task prompts, such as decompiled code, may be truncated and are marked with [...truncated...].
- **Perturbation codes** in the `taxonomy_code` field: `CLEAN` (faithful baseline) and `P1`–`P9`; see the detailed perturbation descriptions below.

---

## Track Descriptions

### Track 1: `soc_tasks_1000`: Structured SOC Micro-Tasks (1,000 cases)

Ten balanced condition classes of 100 cases each:

| Code | Class | Description |
|------|-------|-------------|
| `CLEAN` | Faithful Baseline | Faithful reference text |
| `P1` | Dynamic Behavioral Fabrication | Invented API behaviors, DLL side-loads, or network callbacks |
| `P2` | Threat Entity & Family Substitution | Swapped malware family names or threat actor attributions |
| `P3` | Critical IOC / Mitigation Omission | Dropped indicators of compromise or response actions |
| `P4` | Technical Keyword / Flag Misbinding | Misassigned memory flags, registry keys, or API parameters |
| `P5` | Degenerate Token Looping | Repetitive, degenerate output patterns |
| `P6` | Ungrounded Overconfidence | Unjustified high-confidence assertions without evidence |
| `P7` | Logical Negation & Condition Inversion | Inverted security conditions (e.g., "does not persist" → persists) |
| `P8` | Cross-Entity Fact Swapping | Facts from one sample incorrectly attributed to another |
| `P9` | Format Non-Conformance | Structural or formatting violations breaking report usability |

Task types include: `api_behavior`, `code_analysis`, `detection_guidance`, `family_attribution`, `intent_analysis`, `malware_class_detection`, `malware_classification`, `malware_family_detection`, `risk_assessment`, `technique_explanation`, `threat_identification`, `vulnerability_detection`.

### Track 2: `soc_reports_100`: Long-Form Incident Reports (100 cases)

100 multi-paragraph incident triage reports, each paired with the static-metadata context of a real MalwareBazaar artifact. The reports contain long-form narrative, including behavioral claims (for example registry persistence or C2 beaconing) that the evidence does not support.

## Data Sources

The cases were built from two public sources:

- **LCCD (LCC-LLM):** the code-centric malware dataset used for Track 1, including disassembled x86/x64 Windows API sequences, PE headers and MITRE ATT&CK reference cards. Full dataset: [http://hdl.handle.net/10754/709465](http://hdl.handle.net/10754/709465).
- **[MalwareBazaar](https://bazaar.abuse.ch/):** public malware repository maintained by abuse.ch, used for Track 2 static metadata. The 100 artifacts are Windows PE executables (54), Linux ELF binaries (18), shell scripts (18), archives (5), PowerShell scripts (2), and one each of MSI, JAR and APK.

Short-form outputs (Track 1) were generated with **GenSpect**, an LLM-based SOC reporting system [[cyberdeep.io/genspect](https://www.cyberdeep.io/genspect)]. In the published reports, `CLEAN` entries provide faithful reference text and `P1`–`P9` entries provide corrupted variants. Track 2 long-form reports were generated by prompting production LLMs on the evidence context. Perturbations were injected with deterministic operators, one corruption type per condition.

---
## Scope & Limitations

- **Model-dependent outputs:** Reports reflect the models and prompts used at generation time and may not generalize to other or future models.
- **Synthetic errors:** Perturbed cases contain deliberately injected errors. Their frequency says nothing about how often real models make these errors.
- **Reference snapshots:** MITRE ATT&CK references are pinned to a snapshot fetched on 2026-08-11 from the `mitre/cti` master branch (858 Enterprise techniques; no release-tag version was recorded). Newer techniques are not reflected.
- **No binaries:** No executable content is included. Track 1 contains decompiled code excerpts (RetDec), which may be truncated and inherit the decompiler's limitations. Track 2 contains static metadata only.

---

## Intended Use

- Evaluating hallucination detection and correction methods for security reports.
- Benchmarking claim extraction and claim-verification pipelines against evidence.
- Studying how LLMs fail on specific SOC content such as indicators, persistence, network and attribution claims.

Out-of-scope uses: this dataset is intended for defensive security research and education. It should not be used to produce deceptive security reports or to mislead analysts.

---



---

---

## 👨‍💻 Maintainer

**CyberSar Lab**  
🔗 https://cybersar.kaust.edu.sa/
