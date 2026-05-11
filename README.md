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

#### 2. `detect-stego` — Advanced Steganography Detection
- **Rich Model Steganalysis**: Uses SPAM (Subtractive Pixel Adjacency Matrix) and PSRM-lite projection for advanced statistical anomaly detection, plus HCF-COM for JPEG histograms.
- **Chi-Square (χ²) PoV Attack**: Detects sequential LSB embedding via Pairs-of-Values analysis.
- **RS Analysis**: Detects LSB matching using Regular/Singular group profiling.

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

#### 4. `scan-structure` — Binary Structure Analysis
Perform low-level binary inspection of the image file: validates magic bytes, detects EOF anomalies, checks chunk CRCs in PNGs, identifies suspicious JPEG APP markers, and flags appended trailing data.

```bash
aegis scan-structure IMAGE_PATH
```

```bash
aegis scan-structure ./evidence/photo.jpg
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

### Offensive Steganography

#### 10. `embed` — Covert Payload Embedding
Embed an encrypted, compressed payload covertly into a carrier image. Supports two algorithms optimized for different carrier formats. Prompts securely for a password — the payload is encrypted with **AES-256-GCM** and the key is derived using **Argon2id**.

Supports **plausible deniability** via an optional decoy payload protected by a separate password.

```bash
aegis embed [OPTIONS] CARRIER_PATH PAYLOAD_PATH OUTPUT_PATH
```

| Option | Description |
|---|---|
| `--algo [f5\|adaptive\|j_uniward]` | Algorithm to use **(Required)** |
| `--decoy-payload PATH` | Path to a decoy payload for plausible deniability |

**Algorithm Guide:**

| Algorithm | Best For | Technique |
|---|---|---|
| `j_uniward` | JPEG carriers | (State-of-the-Art) Computes Haar wavelet distortion costs and uses Syndrome-Trellis Codes (STC) for optimal embedding. Highly resistant to rich-model steganalysis. |
| `f5` | JPEG carriers | (1, n, k) Matrix Encoding & Permutative Straddling. Modifies quantized DCT coefficients directly, minimizing changes to evade basic histogram & chi-square attacks. |
| `adaptive` | PNG/lossless carriers | Cost-Function framework (HILL/WOW/MiPOD) with Syndrome-Trellis Codes (STC). Dynamically selects the most textured regions for ternary embedding. |

```bash
# Embed into a JPEG using J-UNIWARD
aegis embed --algo j_uniward carrier.jpg secret.zip stego_output.jpg

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
| `--algo [f5\|adaptive\|j_uniward]` | Algorithm used during embedding **(Required)** |

```bash
aegis extract --algo j_uniward stego_output.jpg recovered_payload.zip
```

---

#### 12. Covert Channels & Multi-Carrier Splitting
AEGIS supports advanced steganography through alternative coverts channels:
- **`palette-embed` / `palette-extract`**: Hides data within the palette ordering of indexed PNG/GIF images (leaves pixel data visually and cryptographically identical).
- **`meta-embed` / `meta-extract`**: Embeds data into `gps` (sub-arcsecond encoding), `icc` (custom private profile tags), or `xmp` (custom namespaces).
- **`split` / `reconstruct`**: Uses Shamir's (k, n) Secret Sharing over GF(2^8) to split a payload into multiple shares that can be embedded into different carrier images.

```bash
# Palette embedding
aegis palette-embed carrier.png payload.bin output.png

# GPS Metadata embedding
aegis meta-embed --channel gps carrier.jpg payload.bin output.jpg

# Split payload into 5 shares (requires any 3 to reconstruct)
aegis split -k 3 -n 5 secret.zip ./shares/
```

---

### Advanced OpSec & Anti-Forensics

AEGIS includes tools that operate outside the image domain to secure your environment and establish trust.

#### 13. `keygen`, `sign-asymmetric`, `verify-asymmetric` — Ed25519 Cryptography
Generate Ed25519 key pairs and sign files using asymmetric cryptography. This establishes true non-repudiation and a verifiable chain of custody without sharing secret keys.

```bash
aegis keygen ./keys/
aegis sign-asymmetric --priv-key ./keys/private_key.pem evidence.jpg
aegis verify-asymmetric --pub-key ./keys/public_key.pem evidence.jpg "base64_signature..."
```

#### 14. `fs-embed`, `fs-extract` — File System Steganography
Hide encrypted payloads inside Linux Extended Attributes (`xattr`). This technique leaves the carrier file's actual data and cryptographic hash (SHA-256) mathematically unmodified, bypassing standard file integrity monitoring.

```bash
aegis fs-embed carrier.txt secret_payload.bin
aegis fs-extract carrier.txt recovered_payload.bin
```

#### 15. `timestomp` — Anti-Forensic Timeline Evasion
Clone the Modified and Accessed (MAC) timestamps from a legitimate reference file to a target file, allowing newly created stego images to blend into a directory's timeline.

```bash
aegis timestomp --clone-from old_photo.jpg new_stego.jpg
```

#### 16. `shred` — Secure File Erasure
Securely overwrite files using a multi-pass algorithm (DoD 5220.22-M style) before deletion, preventing forensic tools from recovering sensitive data from disk sectors.

```bash
aegis shred --passes 3 sensitive_evidence.raw
```

---

## Security Architecture

- **Zero AI/ML dependencies** — all analysis is deterministic and rule-based.
- **AES-256-GCM** authenticated encryption for all embedded payloads.
- **Argon2id** key derivation (memory-hard, resistant to GPU brute-force).
- **HMAC-SHA256 & Ed25519** for cryptographic signing and tamper detection.
- Immutable `ImageObject` model with full forensic audit trail on every operation.
- **DoD 5220.22-M style Shredding** for secure evidence disposal.

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
