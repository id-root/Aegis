

## 1. Forensic Analysis (Optics & Threat Detection)

### `scan`
The primary entry point for general file analysis. Detects polyglot payloads, known malware signatures, and performs deep steganalysis.

**Usage:**
```bash
aegis-cli scan --input <FILE> [--mode <MODE>]
```

**Options:**
- `--mode`:
    - `fast`: Signature and Polyglot check only (Default).
    - `deep`: Adds ELA (Error Level Analysis) and Ghosting detection.
    - `forensics`: Adds PRNU extraction (CPU intensive).

### `analyze` (Vanguard)
Advanced optical physics analysis for verifying image authenticity.

**Usage:**
```bash
aegis-cli analyze --input <FILE> --optics
```

**Capabilities:**
- **Chromatic Aberration (LCA)**: Checks if non-radial edge shifts exist (indicates splicing).
- **CFA Integrity**: Verifies Bayer/X-Trans demosaicing patterns (indicates re-sampling).

---

## 2. Metadata Operations (The Archivist)

### `dump`
Extracts structural metadata, including hidden vendor blocks.

**Usage:**
```bash
aegis-cli dump --input <FILE> [--makernotes]
```

**Options:**
- `--makernotes`: Attempts to decode proprietary binary blobs (Canon/Nikon/Sony) usually ignored by standard tools.

### `edit`
Batch mutation engine for timeline reconstruction or obfuscation.

**Usage:**
```bash
aegis-cli edit --dir <DIRECTORY> --shift-time <SECONDS>
```

**Examples:**
- Shift all photos in `case_12` forward by 1 hour (3600s):
  `aegis-cli edit --dir ./case_12 --shift-time 3600`

### `clean`
Sanitizes metadata to remove PII (GPS, Serial Numbers) before asset release.

**Usage:**
```bash
aegis-cli clean --input <FILE> --output <FILE>
```

---

## 3. Active Defense (The Mirage)

### `cloak`
Applies adversarial perturbations to protect images from automated scraping and AI analysis.

**Usage:**
```bash
aegis-cli cloak --input <FILE> --output <FILE> --mode <MODE>
```

**Modes:**
- `standard`: Anti-HOG (Histogram of Oriented Gradients) adversarial noise.
- `aggressive`: Inject infinite-loop recursive metadata chaff to crash parsing bots.
- `ghost`: Minimal perturbation (Alpha=0.01) for stealth operations.
- `forensics`: Higher intensity (Alpha=0.05) pattern disruption.

### `obfuscate`
Apply "Glitch Art" pixel sorting to render an image unrecognizable to humans and ML models while retaining file validity.

**Usage:**
```bash
aegis-cli defense obfuscate --input <FILE> --output <FILE>
```

---

## 4. Secure Storage (The Vault)

### `vault init`
Initialize a new encrypted-at-rest database (ChaCha20-Poly1305).

**Usage:**
```bash
aegis-cli vault init --path <DB_PATH>
```

### `vault log`
Append an immutable entry to the Merkle DAG audit log.

**Usage:**
```bash
aegis-cli vault log --path <DB_PATH> --action <STRING>
```

### `vault dms-init`
Initialize a Dead Man's Switch (Time-lock) that triggers after a set duration of inactivity.

**Usage:**
```bash
aegis-cli vault dms-init --hours <HOURS>
```

### `vault burn`
Securely delete/shred a file (overwrite patterns + unlink).

**Usage:**
```bash
aegis-cli vault burn --target <FILE>
```

---

## 5. Audio Forensics (Echo)

### `echo analyze`
Performs signal analysis on audio files.

**Usage:**
```bash
aegis-cli echo analyze --file <FILE>
```

**Capabilities:**
- **ENF Matching**: Extracts 50Hz/60Hz hum to verify recording geolocation/timestamp.
- **Splice Detection**: Analyses noise floor consistency to detect edit points.

---

## 6. Computer Vision (Deep Sight)

### `vision fingerprint`
Extracts the Photo Response Non-Uniformity (PRNU) noise pattern unique to the camera sensor.

**Usage:**
```bash
aegis-cli vision fingerprint --file <FILE>
```

### `vision match`
Correlates the noise fingerprints of two images to determine if they were taken by the same device.

**Usage:**
```bash
aegis-cli vision match --file1 <FILE> --file2 <FILE>
```

---

## 7. The Neuron (Actor System)

### `daemon`
Starts the reactive actor system supervisor. This is required for running background plugin tasks.

**Usage:**
```bash
aegis-cli daemon
```

### `neuron watch`
Start an active filesystem watchdog to monitor for new files and auto-trigger scans.

**Usage:**
```bash
aegis-cli neuron watch --path <DIRECTORY>
```

### `plugin load`
Hot-loads a WASM-based forensic parser into the runtime.

**Usage:**

---

## 8. Polyglot Generation (Chameleon)

### `chameleon gifar`
Generates a GIFAR (GIF + JAR) polyglot. This file is a valid image and a valid Java Archive.

**Usage:**
```bash
aegis-cli chameleon gifar --gif <GIF_PATH> --jar <JAR_PATH> --output <OUTPUT_PATH>
```

### `chameleon pdf-html`
Generates a PDF that also functions as valid HTML/JS, useful for testing browser-based PDF renderers.

**Usage:**
```bash
aegis-cli chameleon pdf-html --payload <HTML_FILE_OR_STRING> --output <OUTPUT.PDF>
```


---

## 9. AI Forensics (The Oracle)

### `oracle scan`
Runs a deep learning model (Candle/ResNet) to detect GAN artifacts and DeepFakes.

**Usage:**
```bash
aegis-cli oracle scan --file <FILE_PATH>
```

### `oracle detect`
Runs a generic ONNX computer vision model against an image.

**Usage:**
```bash
aegis-cli oracle detect --input <IMAGE> --model <MODEL.ONNX>
```


