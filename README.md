# Aegis

Project Aegis is a  forensic defense and analysis framework implemented in Rust. It utilizes advanced cryptographic, optical, and signal processing techniques to identify, verify, and sanitize digital assets.

## Core Capabilities

### 🛡️ Phase 0: Foundation
- **Optics**: Chromatic Aberration & CFA analysis for detecting manipulated images.
- **Metadata**: Universal tag parsing (Exif, XMP) with batch mutation and sanitization capabilities.
- **Defense**: Adversarial metadata injection (Anti-HOG) and Glitch Art obfuscation (Pixel Sorting).
- **Chameleon**: Polyglot engine capable of generating GIFAR (GIF+JAR) and PDF+HTML dual-format files.

### 🧠 Phase 1: Hardening
- **The Neuron**: A reactive, actor-based concurrency system with active filesystem watchdog (`libs/aegis-neuron`).
- **Runtime**: Secure WASM-based plugin host for sandboxing third-party parsers (`libs/aegis-runtime`).
- **Sentinel**: Formal verification using Kani and fuzzing test suites to guarantee memory safety (`libs/aegis-metadata`).
- **The Oracle**: Lightweight AI inference engine (ONNX/ResNet) for Deepfake detection and object recognition (`libs/aegis-oracle`).

### 👁️ Phase 2: Knowledge
- **The Vault**: Encrypted-at-rest database (ChaCha20-Poly1305) with Merkle DAG audit logs and Dead Man's Switch (Time-lock) capabilities.
- **Echo**: Audio forensics pipeline capable of extracting Electric Network Frequency (ENF) for geolocation and detecting digital splices (`libs/aegis-echo`).
- **Deep Sight**: Computer vision engine for extracting PRNU (Photo Response Non-Uniformity) camera fingerprints (`libs/aegis-vision`).

## Installation

```bash
git clone https://github.com/id-root/Aegis
cd aegis
cargo build --release
```

## Usage

### Forensics
```bash
# Detect fake images using optical physics
aegis-cli analyze --file evidence.jpg --lca

# Extract Camera Sensor Fingerprint (PRNU)
aegis-cli vision fingerprint --file evidence.jpg

# Match noise pattern between two images
aegis-cli vision match --file1 evidence.jpg --file2 suspect.jpg
```

### Audio Analysis
```bash
# Check for power grid hum (50Hz/60Hz) to verify location
aegis-cli echo analyze --file wiretap.wav
```

### Secure Storage
```bash
# Initialize encrypted vault
aegis-cli vault init --path ./cases.db

# Log secure action
aegis-cli vault log --path ./cases.db --action "Opened Case #9023"
```
*For full usage check:* [Usage file](USAGE.md)

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
