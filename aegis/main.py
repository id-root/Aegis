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
from aegis.core.pipeline import PipelineEngine, OperationRegistry
from aegis.analysis.metadata import extract_metadata
from aegis.analysis.steganography import analyze_steganography, generate_bitplanes
from aegis.analysis.authenticity import analyze_authenticity
from aegis.analysis.authenticity import analyze_authenticity
from aegis.analysis.binary import analyze_binary, extract_trailing_data
from aegis.reporting.reports import print_terminal_report, generate_json_report

# Ensure processing modules are registered
import aegis.processing.core_ops
import aegis.processing.filters
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

@click.group(context_settings={"max_content_width": 120, "terminal_width": 120})
@click.option('--no-banner', is_flag=True, help="Disable ASCII banner output.")
@click.pass_context
def cli(ctx, no_banner):
    """AEGIS: Forensic Image Security Platform"""
    ctx.ensure_object(dict)
    ctx.obj['no_banner'] = no_banner
    if not no_banner:
        display_banner()

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('signature')
@click.option('--key', required=True, help="Secret key used for signing.")
def verify(image_path, signature, key):
    """Verify image integrity via HMAC signature.
    
    Detects tampering by comparing the calculated hash against the written signature.
    """
    console.print(f"[info]Verifying image: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    is_valid = verify_image_signature(img_obj.crypto_hash, signature, key)
    
    if is_valid:
        console.print("[success]✓ Signature is VALID. Image is intact.[/success]")
    else:
        console.print("[error]✗ Signature is INVALID. Image has been tampered with or key is wrong.[/error]")

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--key', required=True, help="Secret key used for signing.")
def sign(image_path, key):
    """Cryptographically sign an image hash."""
    console.print(f"[info]Signing image: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    sig = sign_image_hash(img_obj.crypto_hash, key)
    console.print(f"[success]Image Hash: {img_obj.crypto_hash}[/success]")
    console.print(f"[success]Signature: {sig}[/success]")

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.option('--json-out', type=click.Path(), help="Export report to JSON")
def analyze(image_path, json_out):
    """Run forensic analysis modules on an image.
    
    Includes Metadata, Stego, and ELA.
    """
    console.print(f"[info]Analyzing image: {image_path}...[/info]")
    
    with console.status("[bold cyan]Running forensic engines...") as status:
        meta = extract_metadata(image_path)
        stego = analyze_steganography(image_path)
        auth = analyze_authenticity(image_path)
        binary_res = analyze_binary(image_path)
        
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

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
def detect_stego(image_path):
    """Detect potential steganography in an image."""
    console.print(f"[info]Scanning for steganography in: {image_path}...[/info]")
    results = analyze_steganography(image_path)
    console.print(results)

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
def slice_bitplanes(image_path, output_dir):
    """Extract all 8 bit-planes for analysis.
    
    Extracts and saves all 8 binary bit-planes for steganography analysis.
    """
    console.print(f"[info]Extracting bit-planes from {image_path} into {output_dir}...[/info]")
    generate_bitplanes(image_path, output_dir)
    console.print(f"[success]Bit-planes saved to {output_dir}[/success]")

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
def analyze_binary_cmd(image_path):
    """Run binary analysis for EOF anomalies.
    
    Perform binary and structural analysis to detect EOF anomalies.
    """
    console.print(f"[info]Running binary analysis on: {image_path}...[/info]")
    res = analyze_binary(image_path)
    console.print(res)

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def extract_hidden(image_path, output_path):
    """Extract hidden trailing data after EOF.
    
    Extracts hidden trailing data appended after the end of the file.
    """
    console.print(f"[info]Extracting hidden trailing data from: {image_path}...[/info]")
    success = extract_trailing_data(image_path, output_path)
    if success:
        console.print(f"[success]Extracted trailing data saved to {output_path}.[/success]")
    else:
        console.print("[warning]No trailing data found to extract.[/warning]")

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
def sanitize(image_path, output_path):
    """Remove trace data and metadata from image.
    
    Securely removes all trace data, EXIF metadata, and potentially identifying information,
    saving the result to output_path.
    """
    console.print(f"[info]Sanitizing image: {image_path}...[/info]")
    img_obj = ImageObject.from_file(image_path)
    sanitized = img_obj.apply("sanitize", OperationRegistry.get("sanitize"))
    sanitized.export(output_path, format="PNG")
    console.print(f"[success]Sanitized image saved to {output_path}[/success]")

@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.argument('operations', nargs=-1)
def pipeline(image_path, output_path, operations):
    """
    Execute a deterministic processing pipeline.
    Example: aegis pipeline input.jpg output.jpg "resize width=800 height=600" "sharpen"
    """
    console.print(f"[info]Running pipeline on: {image_path}[/info]")
    engine = PipelineEngine()
    
    for op_str in operations:
        parts = op_str.split()
        op_name = parts[0]
        params = {}
        for p in parts[1:]:
            key, val = p.split('=')
            try:
                # Basic type casting
                if '.' in val:
                    params[key] = float(val)
                elif val.isdigit():
                    params[key] = int(val)
                else:
                    if val.lower() == 'true': val = True
                    elif val.lower() == 'false': val = False
                    params[key] = val
            except:
                params[key] = val
        engine.add_step(op_name, **params)
        console.print(f"  [dim]- Step:[/dim] {op_name} ({params})")
        
    img_obj = ImageObject.from_file(image_path)
    try:
        final_obj = engine.execute(img_obj)
        final_obj.export(output_path)
        console.print(f"[success]Pipeline completed. Saved to {output_path}[/success]")
        # Output audit log
        audit_file = output_path + ".audit.json"
        with open(audit_file, 'w') as f:
            f.write(final_obj.audit_log.export_json())
        console.print(f"[success]Audit log saved to {audit_file}[/success]")
    except Exception as e:
        console.print(f"[error]Pipeline failed: {str(e)}[/error]")

import getpass
from aegis.offensive.crypto import prepare_stego_payload, parse_stego_payload
from aegis.offensive.algorithms.f5_stego import embed_f5_jpeg, extract_f5_jpeg
from aegis.offensive.algorithms.adaptive import embed_adaptive, extract_adaptive

@cli.command()
@click.argument('carrier_path', type=click.Path(exists=True))
@click.argument('payload_path', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--algo', type=click.Choice(['f5', 'adaptive']), required=True, help="Steganography algorithm to use.")
@click.option('--decoy-payload', type=click.Path(exists=True), help="Path to decoy payload for plausible deniability.")
def embed(carrier_path, payload_path, output_path, algo, decoy_payload):
    """Embed a covert payload into an image.
    
    Provides advanced evasion using steganography algorithms.
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
            embed_f5_jpeg(carrier_path, output_path, final_payload)
        elif algo == 'adaptive':
             if not carrier_path.lower().endswith('.png'):
                 console.print("[warning]Adaptive algorithm is best suited for lossless PNG carriers. Using JPEG might result in payload corruption.[/warning]")
             embed_adaptive(carrier_path, output_path, final_payload)
             
        console.print(f"[success]Payload successfully embedded into {output_path}.[/success]")
    except Exception as e:
        console.print(f"[error]Embedding failed: {e}[/error]")


@cli.command()
@click.argument('stego_image', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.option('--algo', type=click.Choice(['f5', 'adaptive']), required=True, help="Steganography algorithm used for embedding.")
def extract(stego_image, output_path, algo):
    """Extract a covert payload from an image."""
    console.print(f"[info]Extracting payload from {stego_image} using {algo.upper()} algorithm...[/info]")
    
    password = getpass.getpass("Enter decryption password: ")
    
    try:
        if algo == 'f5':
            extracted_payload = extract_f5_jpeg(stego_image)
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
        

if __name__ == '__main__':
    cli(obj={})
