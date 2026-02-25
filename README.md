# AEGIS: Forensic Image analysis Platform

AEGIS is a forensic-grade, integrity verification, and manipulation CLI platform. It provides a suite of tools for deep image analysis, metadata sanitization, deterministic processing, binary structure inspection, cryptographic verification, and advanced offensive steganography — all with no machine learning dependencies.

---

## Installation

### From Source
Ensure you have **Python 3.10+** installed. Install Aegis and its dependencies using `pip`:

```bash
pip install -e .
```

> **Note:** System-level dependencies like `libvips` and `libopencv` may be required depending on your platform.

### Pre-built Binary (Linux)
Download the latest pre-built binary from the [Releases page](../../releases) — no Python installation required.

```bash
chmod +x aegis
./aegis --help
```

---

## Usage Overview

The AEGIS CLI uses the `aegis` command followed by a specific subcommand.

```bash
aegis [OPTIONS] COMMAND [ARGS]...
```

**Global Options:**
- `--no-banner` — Disable the ASCII banner output.
- `--help` — Show the global help message and exit.

---

## Command Reference

### Defensive Forensics

#### 1. `analyze` — Full Forensic Analysis
Run all forensic engines on an image: Metadata extraction, Steganography statistical analysis, Error Level Analysis (ELA), authenticity checks, and binary structure inspection.

```bash
aegis analyze [OPTIONS] IMAGE_PATH
```

| Option | Description |
|---|---|
| `--json-out PATH` | Export the full analysis report to a JSON file |

```bash
aegis analyze --json-out report.json ./evidence/photo.jpg
```

---

#### 2. `detect-stego` — Steganography Detection
Scan an image for statistical anomalies indicating hidden data payloads. Reports entropy, PVD variance, bit-plane irregularities, and a suspicion score.

```bash
aegis detect-stego IMAGE_PATH
```

```bash
aegis detect-stego ./evidence/suspect_image.png
```

---

#### 3. `slice-bitplanes` — Bit-Plane Extraction
Extract and save all 8 binary bit-planes from each colour channel for visual steganography analysis.

```bash
aegis slice-bitplanes IMAGE_PATH OUTPUT_DIR
```

```bash
aegis slice-bitplanes suspect.png ./bitplanes/
```

---

#### 4. `analyze-binary` — Binary Structure Analysis
Perform low-level binary inspection of the image file: validates magic bytes, detects EOF anomalies, and flags appended trailing data.

```bash
aegis analyze-binary IMAGE_PATH
```

```bash
aegis analyze-binary ./evidence/photo.jpg
```

---

#### 5. `extract-hidden` — Extract Trailing Data
If binary analysis detects data appended after the file's end-of-file marker, this command extracts and saves it.

```bash
aegis extract-hidden IMAGE_PATH OUTPUT_PATH
```

```bash
aegis extract-hidden photo_with_appended_data.jpg extracted_payload.bin
```

---

#### 6. `sanitize` — Metadata Sanitization
Securely strip all EXIF metadata, embedded profiles, and trace data from an image. The sanitized output is saved as a clean PNG.

```bash
aegis sanitize IMAGE_PATH OUTPUT_PATH
```

```bash
aegis sanitize input.jpg sanitized_output.png
```

---

#### 7. `sign` — Cryptographic Signing
Cryptographically sign an image's SHA-256 hash using HMAC to establish a verifiable chain of custody.

```bash
aegis sign [OPTIONS] IMAGE_PATH
```

| Option | Description |
|---|---|
| `--key TEXT` | Secret key for HMAC signing **(Required)** |

```bash
aegis sign --key "my_secret_key" evidence.jpg
```

---

#### 8. `verify` — Integrity Verification
Verify an image against its previously generated HMAC signature to detect any tampering or unauthorized modifications.

```bash
aegis verify [OPTIONS] IMAGE_PATH SIGNATURE
```

| Option | Description |
|---|---|
| `--key TEXT` | Secret key used for verification **(Required)** |

```bash
aegis verify --key "my_secret_key" evidence.jpg "a1b2c3d4e5f6..."
```

---

#### 9. `pipeline` — Deterministic Processing Pipeline
Execute a chain of image processing operations in a reproducible, auditable sequence. An audit log JSON is automatically saved alongside the output.

```bash
aegis pipeline IMAGE_PATH OUTPUT_PATH [OPERATIONS]...
```

Supported operations: `resize`, `sharpen`, `blur`, `grayscale`, `rotate`

```bash
aegis pipeline input.jpg output.jpg "resize width=800 height=600" "sharpen"
```

---

### Offensive Steganography

#### 10. `embed` — Covert Payload Embedding
Embed an encrypted, compressed payload covertly into a carrier image. Supports two algorithms optimized for different carrier formats. Prompts securely for a password — the payload is encrypted with **AES-256-GCM** and the key is derived using **Argon2id**.

Supports **plausible deniability** via an optional decoy payload protected by a separate password.

```bash
aegis embed [OPTIONS] CARRIER_PATH PAYLOAD_PATH OUTPUT_PATH
```

| Option | Description |
|---|---|
| `--algo [f5\|adaptive]` | Algorithm to use **(Required)** |
| `--decoy-payload PATH` | Path to a decoy payload for plausible deniability |

**Algorithm Guide:**

| Algorithm | Best For | Technique |
|---|---|---|
| `f5` | JPEG carriers | Modifies quantized DCT coefficients directly — evades histogram & chi-square attacks |
| `adaptive` | PNG/lossless carriers | Uses Canny edge detection to embed only in high-texture regions — evades statistical analysis |

```bash
# Embed into a JPEG using F5
aegis embed --algo f5 carrier.jpg secret.zip stego_output.jpg

# Embed into a PNG with a decoy (plausible deniability)
aegis embed --algo adaptive --decoy-payload decoy.txt carrier.png secret.bin stego_output.png
```

---

#### 11. `extract` — Covert Payload Extraction
Extract and decrypt a previously embedded payload from a stego image. Securely prompts for the password and automatically handles the plausible deniability structure.

```bash
aegis extract [OPTIONS] STEGO_IMAGE OUTPUT_PATH
```

| Option | Description |
|---|---|
| `--algo [f5\|adaptive]` | Algorithm used during embedding **(Required)** |

```bash
aegis extract --algo f5 stego_output.jpg recovered_payload.zip
```

---

## Security Architecture

- **Zero AI/ML dependencies** — all analysis is deterministic and rule-based.
- **AES-256-GCM** authenticated encryption for all embedded payloads.
- **Argon2id** key derivation (memory-hard, resistant to GPU brute-force).
- **HMAC-SHA256** for image signing and tamper detection.
- Immutable `ImageObject` model with full forensic audit trail on every operation.

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=aegis tests/
```
