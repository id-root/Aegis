import click
import json
import os
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

from aegis.core.image_object import ImageObject
from aegis.core.signing import sign_image_hash, verify_image_signature

from aegis.analysis.metadata import extract_metadata
from aegis.analysis.steganography import analyze_steganography, generate_bitplanes
from aegis.analysis.authenticity import analyze_authenticity
from aegis.analysis.binary import extract_trailing_data
from aegis.analysis.structure_validator import scan_structure
from aegis.analysis.rich_model import analyze_rich_model
from aegis.reporting.reports import print_terminal_report, generate_json_report
from aegis.security.shredder import secure_shred
from aegis.security.timestomp import clone_timestamps
from aegis.offensive.fs_stego import embed_xattr, extract_xattr
from aegis.core.signing import generate_key_pair, sign_image_hash_asymmetric, verify_image_signature_asymmetric

import aegis.security.sanitization

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green"
})
console = Console(theme=custom_theme)

def display_banner():
    banner_text = """
    █████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║
   ██║  ██║███████╗╚██████╔╝██║███████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
    """
    styled_text = Text(banner_text, style="bold cyan")
    panel = Panel(styled_text, title="[bold magenta]Forensic-Grade Image Security[/]", subtitle="[dim]v0.1.0[/]", border_style="cyan")
    console.print(panel)
    console.print()

@click.group(
    context_settings={"max_content_width": 120, "terminal_width": 120, "help_option_names": ["-h", "--help"]},
    epilog="Run 'aegis COMMAND --help' for more information on a command."
)
@click.option('--no-banner', is_flag=True, help="Disable ASCII banner output.")
@click.pass_context
def cli(ctx, no_banner):
    """
    AEGIS: Forensic Image Security Platform
    
    A forensic-grade toolkit for image analysis, integrity verification, 
    metadata sanitization, and offensive steganography.
    """
    ctx.ensure_object(dict)
    ctx.obj['no_banner'] = no_banner
    if not no_banner:
        display_banner()

@cli.command(help="Verify image integrity via HMAC signature.")
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('signature')
@click.option('--key', required=True, help="Secret key used for signature verification.")
def verify(image_path, signature, key):
    """
    Verify image integrity against a known HMAC signature.
    
    Detects any unauthorized modifications or tampering by comparing the 
    re-calculated cryptographic hash of the image against the provided signature.
    """
    console.print(f"[info]Verifying image: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    is_valid = verify_image_signature(img_obj.crypto_hash, signature, key)
    
    if is_valid:
        console.print("[success]✓ Signature is VALID. Image is intact.[/success]")
    else:
        console.print("[error]✗ Signature is INVALID. Image has been tampered with or key is wrong.[/error]")

@cli.command(help="Cryptographically sign an image hash.")
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--key', required=True, help="Secret key used for generating the HMAC signature.")
def sign(image_path, key):
    """
    Generate a cryptographic signature for an image.
    
    Computes a deterministic SHA-256 hash of the image pixel data and signs it 
    with the provided secret key using HMAC, establishing a verifiable chain of custody.
    """
    console.print(f"[info]Signing image: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    sig = sign_image_hash(img_obj.crypto_hash, key)
    console.print(f"[success]Image Hash: {img_obj.crypto_hash}[/success]")
    console.print(f"[success]Signature: {sig}[/success]")

@cli.command(help="Generate an Ed25519 key pair for asymmetric signing.")
@click.argument('output_dir', type=click.Path(exists=True, file_okay=False, dir_okay=True))
def keygen(output_dir):
    """
    Generate an Ed25519 public/private key pair.
    
    Saves `private_key.pem` and `public_key.pem` in the specified directory.
    Keep the private key secure; distribute the public key for verification.
    """
    priv_pem, pub_pem = generate_key_pair()
    
    priv_path = os.path.join(output_dir, "private_key.pem")
    pub_path = os.path.join(output_dir, "public_key.pem")
    
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
        
    console.print(f"[success]Keys generated successfully![/success]")
    console.print(f"Private Key: {priv_path} [bold red](KEEP SECRET)[/]")
    console.print(f"Public Key: {pub_path}")

@cli.command(name="sign-asymmetric", help="Sign an image using an Ed25519 private key.")
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--priv-key', required=True, type=click.Path(exists=True), help="Path to the Ed25519 private key PEM file.")
def sign_asymmetric(image_path, priv_key):
    """
    Generate a verifiable asymmetric signature.
    
    Uses Ed25519 public-key cryptography. This allows true non-repudiation 
    as the signature can be verified without sharing the secret key.
    """
    console.print(f"[info]Signing image asymmetrically: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    
    with open(priv_key, "rb") as f:
        priv_pem = f.read()
        
    sig = sign_image_hash_asymmetric(img_obj.crypto_hash, priv_pem)
    console.print(f"[success]Image Hash: {img_obj.crypto_hash}[/success]")
    console.print(f"[success]Ed25519 Signature: {sig}[/success]")

@cli.command(name="verify-asymmetric", help="Verify an Ed25519 image signature.")
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('signature')
@click.option('--pub-key', required=True, type=click.Path(exists=True), help="Path to the Ed25519 public key PEM file.")
def verify_asymmetric(image_path, signature, pub_key):
    """
    Verify an asymmetric signature using the signer's public key.
    """
    console.print(f"[info]Verifying asymmetric signature for: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    
    with open(pub_key, "rb") as f:
        pub_pem = f.read()
        
    is_valid = verify_image_signature_asymmetric(img_obj.crypto_hash, signature, pub_pem)
    
    if is_valid:
        console.print("[success]✓ Ed25519 Signature is VALID. Image is intact.[/success]")
    else:
        console.print("[error]✗ Ed25519 Signature is INVALID. Image tampered or key mismatch.[/error]")

@cli.command(help="Run full forensic analysis modules on an image.")
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--json-out', type=click.Path(), help="Export the comprehensive report to a JSON file.")
def analyze(image_path, json_out):
    """
    Execute all forensic analysis engines on a target image.
    
    Includes:
      - Metadata Extraction (EXIF, IPTC, XMP)
      - Steganography Detection (Chi-Square, RS Analysis, Entropy, PVD)
      - Authenticity Verification (Error Level Analysis)
      - Binary Structure Inspection (EOF anomalies, appended data)
    """
    console.print(f"[info]Analyzing image: {image_path}...[/info]")
    
    with console.status("[bold cyan]Running forensic engines...") as status:
        meta = extract_metadata(image_path)
        # Use new rich model for steganography
        stego = analyze_rich_model(image_path)
        auth = analyze_authenticity(image_path)
        # Use new structure scanner
        binary_res = scan_structure(image_path)
        
    results = {
        "metadata": meta,
        "steganography": stego,
        "authenticity": auth,
        "binary": binary_res
    }
    
    print_terminal_report(console, results, image_path)
    
    if json_out:
        generate_json_report(results, json_out)
        console.print(f"[success]Report saved to {json_out}[/success]")

@cli.command(help="Detect potential steganography in an image.")
@click.argument('image_path', type=click.Path(exists=True))
def detect_stego(image_path):
    """
    Scan an image for statistical anomalies indicating hidden data.
    
    Uses Chi-Square (PoV) attacks, RS analysis, and LSB variance checks
    to compute a weighted suspicion score.
    """
    console.print(f"[info]Scanning for steganography in: {image_path}...[/info]")
    results = analyze_steganography(image_path)
    console.print(results)

@cli.command(help="Extract all 8 bit-planes for visual analysis.")
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
def slice_bitplanes(image_path, output_dir):
    """
    Deconstruct the image into its binary bit-planes.
    
    Extracts and saves all 8 bit-planes (from MSB to LSB) for each colour 
    channel. Essential for manual visual inspection of steganographic noise.
    """
    console.print(f"[info]Extracting bit-planes from {image_path} into {output_dir}...[/info]")
    generate_bitplanes(image_path, output_dir)
    console.print(f"[success]Bit-planes saved to {output_dir}[/success]")

@cli.command(name="scan-structure", help="Run binary analysis for format structure and EOF anomalies.")
@click.argument('image_path', type=click.Path(exists=True))
def scan_structure_cmd(image_path):
    """
    Perform deep binary structure inspection.
    
    Validates file magic bytes and detects structural anomalies, such as 
    data appended after the End-Of-File (EOF) marker, suspicious chunks, and markers.
    """
    console.print(f"[info]Running structural binary analysis on: {image_path}...[/info]")
    res = scan_structure(image_path)
    console.print(res)

@cli.command(name="extract-hidden", help="Extract hidden trailing data after EOF.")
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def extract_hidden(image_path, output_path):
    """
    Recover binary data appended beyond the image's EOF marker.
    
    If the `analyze-binary` command flags trailing data, use this tool to 
    extract the hidden payload to a separate file.
    """
    console.print(f"[info]Extracting hidden trailing data from: {image_path}...[/info]")
    success = extract_trailing_data(image_path, output_path)
    if success:
        console.print(f"[success]Extracted trailing data saved to {output_path}.[/success]")
    else:
        console.print("[warning]No trailing data found to extract.[/warning]")

@cli.command(help="Securely remove trace data and metadata from an image.")
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def sanitize(image_path, output_path):
    """
    Perform forensic sanitization of an image.
    
    Strips all EXIF metadata, embedded colour profiles, and trace data. 
    The resulting image is re-encoded as a clean PNG, ensuring no residual 
    identifying information remains.
    """
    console.print(f"[info]Sanitizing image: {image_path}...[/info]")
    from aegis.security.sanitization import sanitize_image
    img_obj = ImageObject.from_file(image_path)
    sanitized = img_obj.apply("sanitize", sanitize_image)
    sanitized.export(output_path, format="PNG")
    console.print(f"[success]Sanitized image saved to {output_path}[/success]")

@cli.command(help="Securely erase a file to prevent forensic recovery.")
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--passes', default=3, type=int, help="Number of overwrite passes (default: 3).")
def shred(file_path, passes):
    """
    Shred a file using multi-pass overwriting.
    
    Performs a DoD 5220.22-M style overwrite (zeros, ones, random data) 
    before unlinking the file, rendering forensic data recovery impossible.
    """
    console.print(f"[warning]WARNING: Securely shredding {file_path} with {passes} passes...[/warning]")
    try:
        success = secure_shred(file_path, passes)
        if success:
            console.print("[success]File securely shredded and deleted.[/success]")
    except Exception as e:
        console.print(f"[error]Shredding failed: {e}[/error]")

@cli.command(help="Clone MAC timestamps from a reference file (Anti-Forensics).")
@click.argument('target_file', type=click.Path(exists=True))
@click.option('--clone-from', required=True, type=click.Path(exists=True), help="Reference file to copy timestamps from.")
def timestomp(target_file, clone_from):
    """
    Manipulate file system timestamps.
    
    Copies the Access (atime) and Modified (mtime) timestamps from the 
    reference file to the target file. Useful for making newly created 
    stego payloads blend into existing directory structures.
    """
    console.print(f"[info]Cloning timestamps from {clone_from} to {target_file}...[/info]")
    try:
        success = clone_timestamps(clone_from, target_file)
        if success:
            console.print("[success]Timestamps successfully cloned![/success]")
    except Exception as e:
        console.print(f"[error]Timestomping failed: {e}[/error]")


import getpass
from aegis.offensive.crypto import prepare_stego_payload, parse_stego_payload
from aegis.offensive.algorithms.f5_stego import embed_f5_jpeg, extract_f5_jpeg
from aegis.offensive.algorithms.adaptive import embed_adaptive, extract_adaptive
from aegis.offensive.algorithms.j_uniward import embed_j_uniward, extract_j_uniward
from aegis.offensive.channels.palette_stego import embed_palette, extract_palette
from aegis.offensive.channels.metadata_channel import (
    embed_gps_channel, extract_gps_channel,
    embed_icc_channel, extract_icc_channel,
    embed_xmp_channel, extract_xmp_channel
)
from aegis.offensive.channels.multi_carrier import split_payload_for_carriers, reconstruct_payload_from_shares

@cli.command(help="Embed a covert payload into an image (Offensive Steganography).")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('payload_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--algo', type=click.Choice(['f5', 'adaptive', 'j_uniward']), required=True, 
              help="Steganography algorithm: 'f5' or 'j_uniward' for JPEG, 'adaptive' for PNG.")
@click.option('--decoy-payload', type=click.Path(exists=True), 
              help="Path to a decoy payload file for plausible deniability.")
def embed(carrier_path, payload_path, output_path, algo, decoy_payload):
    """
    Embed an encrypted, compressed payload covertly into a carrier image.
    
    Payloads are encrypted with AES-256-GCM (key derived via Argon2id).
    Supports Plausible Deniability by nesting the true payload inside a 
    decoy payload container, each protected by separate passwords.
    """
    console.print(f"[info]Preparing payload for embedding...[/info]")
    
    with open(payload_path, 'rb') as f:
        primary_data = f.read()
        
    password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        console.print("[error]Passwords do not match![/error]")
        return
        
    decoy_data = None
    decoy_password = None
    if decoy_payload:
        with open(decoy_payload, 'rb') as f:
            decoy_data = f.read()
        decoy_password = getpass.getpass("Enter DECOY encryption password: ")
        
    try:
        final_payload = prepare_stego_payload(
            primary_data=primary_data,
            primary_password=password,
            decoy_data=decoy_data,
            decoy_password=decoy_password
        )
    except Exception as e:
        console.print(f"[error]Encryption failed: {e}[/error]")
        return
        
    console.print(f"[info]Embedding {len(final_payload)} bytes into {carrier_path} using {algo.upper()} algorithm...[/info]")
    
    try:
        if algo == 'f5':
            if not carrier_path.lower().endswith(('.jpg', '.jpeg')):
                 console.print("[error]F5 algorithm requires a JPEG carrier image.[/error]")
                 return
            embed_f5_jpeg(carrier_path, output_path, final_payload, password=password)
        elif algo == 'j_uniward':
            if not carrier_path.lower().endswith(('.jpg', '.jpeg')):
                 console.print("[error]J-UNIWARD algorithm requires a JPEG carrier image.[/error]")
                 return
            embed_j_uniward(carrier_path, output_path, final_payload, password=password)
        elif algo == 'adaptive':
             if not carrier_path.lower().endswith('.png'):
                 console.print("[warning]Adaptive algorithm is best suited for lossless PNG carriers. Using JPEG might result in payload corruption.[/warning]")
             embed_adaptive(carrier_path, output_path, final_payload)
             
        console.print(f"[success]Payload successfully embedded into {output_path}.[/success]")
    except Exception as e:
        console.print(f"[error]Embedding failed: {e}[/error]")


@cli.command(help="Extract a covert payload from an image (Offensive Steganography).")
@click.argument('stego_image', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--algo', type=click.Choice(['f5', 'adaptive', 'j_uniward']), required=True, 
              help="Steganography algorithm used during embedding ('f5', 'j_uniward', or 'adaptive').")
def extract(stego_image, output_path, algo):
    """
    Extract and decrypt a previously embedded payload from a stego image.
    
    Securely prompts for the password and automatically handles extracting 
    the correct payload (either the true payload or the decoy, depending 
    on the password provided).
    """
    console.print(f"[info]Extracting payload from {stego_image} using {algo.upper()} algorithm...[/info]")
    
    password = getpass.getpass("Enter decryption password: ")
    
    try:
        if algo == 'f5':
            extracted_payload = extract_f5_jpeg(stego_image, password=password)
        elif algo == 'j_uniward':
            extracted_payload = extract_j_uniward(stego_image, password=password)
        elif algo == 'adaptive':
            extracted_payload = extract_adaptive(stego_image)
            
        if not extracted_payload:
             console.print("[error]Failed to extract raw payload. File may not contain steganography or is corrupted.[/error]")
             return
             
    except Exception as e:
        console.print(f"[error]Extraction failed: {e}[/error]")
        return
        
    try:
        decrypted_data = parse_stego_payload(extracted_payload, password)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        console.print(f"[success]Payload successfully extracted and decrypted to {output_path}![/success]")
    except ValueError as e:
        console.print(f"[error]{e}[/error]")
        

@cli.command(name="fs-embed", help="Hide a payload in File System Extended Attributes.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('payload_path', type=click.Path(exists=True))
def fs_embed(carrier_path, payload_path):
    """
    Embed data into Linux Extended Attributes (xattr).
    
    Hides the payload within the file system metadata rather than modifying 
    the actual file contents. The carrier's cryptographic hash (SHA-256) 
    remains completely unchanged.
    """
    console.print(f"[info]Embedding payload into xattr of {carrier_path}...[/info]")
    
    with open(payload_path, 'rb') as f:
        primary_data = f.read()
        
    password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        console.print("[error]Passwords do not match![/error]")
        return
        
    try:
        final_payload = prepare_stego_payload(
            primary_data=primary_data,
            primary_password=password,
            decoy_data=None,
            decoy_password=None
        )
    except Exception as e:
        console.print(f"[error]Encryption failed: {e}[/error]")
        return
        
    try:
        embed_xattr(carrier_path, final_payload)
        console.print(f"[success]Payload successfully hidden in xattr of {carrier_path}.[/success]")
    except Exception as e:
        console.print(f"[error]Embedding failed: {e}[/error]")

@cli.command(name="fs-extract", help="Extract a payload from File System Extended Attributes.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def fs_extract(carrier_path, output_path):
    """
    Extract data hidden in Linux Extended Attributes (xattr).
    """
    console.print(f"[info]Extracting xattr payload from {carrier_path}...[/info]")
    
    try:
        extracted_payload = extract_xattr(carrier_path)
        if not extracted_payload:
            console.print("[error]No payload found in extended attributes.[/error]")
            return
            
        password = getpass.getpass("Enter decryption password: ")
        decrypted_data = parse_stego_payload(extracted_payload, password)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        console.print(f"[success]Payload extracted and decrypted to {output_path}![/success]")
    except Exception as e:
        console.print(f"[error]Extraction failed: {e}[/error]")

@cli.command(name="palette-embed", help="Hide a payload in palette ordering.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('payload_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def palette_embed_cmd(carrier_path, payload_path, output_path):
    console.print(f"[info]Embedding payload into palette of {carrier_path}...[/info]")
    with open(payload_path, 'rb') as f:
        primary_data = f.read()
    password = getpass.getpass("Enter encryption password: ")
    try:
        final_payload = prepare_stego_payload(primary_data=primary_data, primary_password=password)
        embed_palette(carrier_path, output_path, final_payload, password=password)
        console.print(f"[success]Payload successfully hidden in palette of {output_path}.[/success]")
    except Exception as e:
        console.print(f"[error]Embedding failed: {e}[/error]")

@cli.command(name="palette-extract", help="Extract a payload from palette ordering.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def palette_extract_cmd(carrier_path, output_path):
    console.print(f"[info]Extracting palette payload from {carrier_path}...[/info]")
    password = getpass.getpass("Enter decryption password: ")
    try:
        extracted_payload = extract_palette(carrier_path, password=password)
        if not extracted_payload:
            console.print("[error]No payload found in palette.[/error]")
            return
        decrypted_data = parse_stego_payload(extracted_payload, password)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        console.print(f"[success]Payload extracted and decrypted to {output_path}![/success]")
    except Exception as e:
        console.print(f"[error]Extraction failed: {e}[/error]")

@cli.command(name="meta-embed", help="Hide a payload in metadata channels.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('payload_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--channel', type=click.Choice(['gps', 'icc', 'xmp']), required=True)
def meta_embed_cmd(carrier_path, payload_path, output_path, channel):
    console.print(f"[info]Embedding payload into {channel} of {carrier_path}...[/info]")
    with open(payload_path, 'rb') as f:
        primary_data = f.read()
    password = getpass.getpass("Enter encryption password: ")
    try:
        final_payload = prepare_stego_payload(primary_data=primary_data, primary_password=password)
        if channel == 'gps':
            embed_gps_channel(carrier_path, output_path, final_payload)
        elif channel == 'icc':
            embed_icc_channel(carrier_path, output_path, final_payload)
        elif channel == 'xmp':
            embed_xmp_channel(carrier_path, output_path, final_payload)
        console.print(f"[success]Payload successfully hidden in {channel} of {output_path}.[/success]")
    except Exception as e:
        console.print(f"[error]Embedding failed: {e}[/error]")

@cli.command(name="meta-extract", help="Extract a payload from metadata channels.")
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--channel', type=click.Choice(['gps', 'icc', 'xmp']), required=True)
def meta_extract_cmd(carrier_path, output_path, channel):
    console.print(f"[info]Extracting {channel} payload from {carrier_path}...[/info]")
    password = getpass.getpass("Enter decryption password: ")
    try:
        if channel == 'gps':
            extracted_payload = extract_gps_channel(carrier_path)
        elif channel == 'icc':
            extracted_payload = extract_icc_channel(carrier_path)
        elif channel == 'xmp':
            extracted_payload = extract_xmp_channel(carrier_path)
            
        if not extracted_payload:
            console.print(f"[error]No payload found in {channel}.[/error]")
            return
        decrypted_data = parse_stego_payload(extracted_payload, password)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        console.print(f"[success]Payload extracted and decrypted to {output_path}![/success]")
    except Exception as e:
        console.print(f"[error]Extraction failed: {e}[/error]")

@cli.command(name="split", help="Split payload for multi-carrier embedding.")
@click.argument('payload_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path(dir_okay=True))
@click.option('-k', type=int, required=True, help="Minimum shares required to reconstruct")
@click.option('-n', type=int, required=True, help="Total shares to generate")
def split_cmd(payload_path, output_dir, k, n):
    console.print(f"[info]Splitting payload {payload_path} into {n} shares (threshold {k})...[/info]")
    with open(payload_path, 'rb') as f:
        primary_data = f.read()
    password = getpass.getpass("Enter encryption password: ")
    try:
        final_payload = prepare_stego_payload(primary_data=primary_data, primary_password=password)
        shares = split_payload_for_carriers(final_payload, k, n)
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        for i, share in enumerate(shares):
            share_path = os.path.join(output_dir, f"share_{i+1}.bin")
            with open(share_path, 'wb') as f:
                f.write(share)
            console.print(f"Share {i+1} saved to {share_path}")
        console.print("[success]Splitting successful.[/success]")
    except Exception as e:
        console.print(f"[error]Splitting failed: {e}[/error]")

@cli.command(name="reconstruct", help="Reconstruct split payload.")
@click.argument('shares', nargs=-1, type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def reconstruct_cmd(shares, output_path):
    console.print(f"[info]Reconstructing payload from {len(shares)} shares...[/info]")
    password = getpass.getpass("Enter decryption password: ")
    try:
        share_blobs = []
        for s in shares:
            with open(s, 'rb') as f:
                share_blobs.append(f.read())
                
        extracted_payload = reconstruct_payload_from_shares(share_blobs)
        decrypted_data = parse_stego_payload(extracted_payload, password)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        console.print(f"[success]Payload reconstructed and decrypted to {output_path}![/success]")
    except Exception as e:
        console.print(f"[error]Reconstruction failed: {e}[/error]")

if __name__ == '__main__':
    cli(obj={})
