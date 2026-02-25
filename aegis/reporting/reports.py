import json
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

def generate_json_report(data: Dict[str, Any], output_path: str):
    """Exports analysis data to JSON."""
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4, default=str)

def print_terminal_report(console: Console, analysis_results: Dict[str, Any], image_path: str):
    """
    Prints a beautiful tabular terminal report using Rich.
    """
    console.print(f"\\n[bold cyan]Forensic Report for: {image_path}[/]")
    
    # Metadata Table
    meta = analysis_results.get("metadata", {})
    if meta and "error" not in meta:
        table = Table(title="[bold blue]Image Metadata[/]", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Format", str(meta.get("format", "N/A")))
        table.add_row("Mode", str(meta.get("mode", "N/A")))
        table.add_row("Size", str(meta.get("size", "N/A")))
        
        exif = meta.get("exif", {})
        if exif:
            for k, v in exif.items():
                table.add_row(f"EXIF: {k}", str(v))
        
        gps = meta.get("gps", {})
        if gps:
            table.add_row("GPS Latitude", f"{gps.get('latitude', 'N/A')}")
            table.add_row("GPS Longitude", f"{gps.get('longitude', 'N/A')}")
            table.add_row("Google Maps URL", f"[link={gps.get('google_maps_url')}]{gps.get('google_maps_url')}[/link]")
            
        timeline = meta.get("timeline", {})
        if timeline:
            table.add_row("Timeline Status", f"[bold yellow]{timeline.get('status', 'OK')}[/]")
            table.add_row("Timeline Span (s)", str(timeline.get("span_seconds", 0)))
            
        console.print(table)
        
    # Steganography Table
    stego = analysis_results.get("steganography", {})
    if stego and "error" not in stego:
        table = Table(title="[bold red]Steganography Analysis[/]", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        
        table.add_row("Entropy", f"{stego.get('entropy', 0):.4f}")
        
        pvd = stego.get("pvd_statistics", {})
        if pvd:
            table.add_row("PVD Mean Diff", f"{pvd.get('mean_absolute_difference', 0):.2f}")
            table.add_row("PVD Variance", f"{pvd.get('difference_variance', 0):.2f}")
        
        score = stego.get("stego_suspicion_score", 0)
        score_style = "bold red" if score > 50 else ("bold yellow" if score > 0 else "bold green")
        table.add_row("Suspicion Score", f"[{score_style}]{score}/100[/]")
        
        anomalies = stego.get("lsb_anomalies", [])
        if anomalies:
            table.add_row("Anomalies", f"[bold red]{', '.join(anomalies)}[/]")
        else:
            table.add_row("Anomalies", "[green]None[/]")
            
        console.print(table)
        
    # Authenticity Table
    auth = analysis_results.get("authenticity", {})
    if auth and "error" not in auth:
        table = Table(title="[bold yellow]Authenticity (ELA)[/]", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        
        diff = auth.get("ela_max_difference", 0)
        status = auth.get("status", "UNKNOWN")
        status_style = "bold green" if status == "OK" else "bold red"
        
        table.add_row("Max Compression Diff", f"{diff:.2f}")
        table.add_row("Status", f"[{status_style}]{status}[/]")
        
        if "has_custom_dqt" in auth:
            table.add_row("DQT Analysis", "[bold yellow]Custom/Software Signature Present[/]")
            
        noise = auth.get("noise_analysis", {})
        if noise:
            noise_status = noise.get("status", "OK")
            n_style = "bold red" if "SUSPICIOUS" in noise_status else "bold green"
            table.add_row("Noise Variance", f"[{n_style}]{noise_status}[/]")
            
        thumb = auth.get("thumbnail_analysis", {})
        if thumb and thumb.get("has_thumbnail"):
            thumb_status = thumb.get("status", "OK")
            t_style = "bold red" if "SUSPICIOUS" in thumb_status else "bold green"
            table.add_row("EXIF Thumbnail", f"[{t_style}]{thumb_status}[/]")
            
        console.print(table)
        
    # Binary Table
    binary = analysis_results.get("binary", {})
    if binary and "error" not in binary:
        table = Table(title="[bold magenta]Binary & Structure Analysis[/]", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        table.add_row("Magic Bytes", str(binary.get("magic_bytes", "Unknown")))
        table.add_row("File Size", str(binary.get("file_size", 0)))
        
        eof_anomaly = binary.get("eof_anomaly", False)
        anomaly_style = "bold red" if eof_anomaly else "bold green"
        table.add_row("EOF Anomaly", f"[{anomaly_style}]{eof_anomaly}[/]")
        
        if eof_anomaly:
            table.add_row("Trailing Data Size", f"[bold red]{binary.get('trailing_data_size', 0)} bytes[/]")
            
        anomalies = binary.get("anomalies", [])
        if anomalies:
            for anomaly in anomalies:
                table.add_row("Anomaly", f"[bold orange]{anomaly}[/]")
                
        console.print(table)

    console.print(Panel("[bold green]Analysis Complete.[/]", border_style="green"))
