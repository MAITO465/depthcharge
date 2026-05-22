#!/usr/bin/env python
import os
import sys
import subprocess
import shutil

# Try importing Rich for advanced console formatting
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
    from rich import print as rprint
    rich_available = True
    console = Console()
except ImportError:
    rich_available = False

def print_header():
    title = "DEPTHCHARGE Threat Analyzer Launcher"
    subtitle = "Secure Dependency Scanning System (PyPI & NPM)"
    if rich_available:
        console.clear()
        panel = Panel(
            Align.center(
                Text.assemble(
                    (f"⚡ {title} ⚡\n", "bold cyan"),
                    (subtitle, "italic yellow")
                )
            ),
            border_style="cyan"
        )
        console.print(panel)
    else:
        # Clear screen fallback
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 60)
        print(f"         {title}         ")
        print(f"      {subtitle}      ")
        print("=" * 60)

def print_menu():
    options = [
        ("1", "Start Web Dashboard (Flask server at http://localhost:5001)"),
        ("2", "Scan Package (CLI Mode)"),
        ("3", "Scan File (requirements.txt / package.json)"),
        ("4", "View Scan History"),
        ("5", "Exit")
    ]
    if rich_available:
        menu_text = Text()
        for opt, desc in options:
            menu_text.append(f" [{opt}] ", style="bold green")
            menu_text.append(f"{desc}\n", style="white")
        console.print(Panel(menu_text, title="Select Option", border_style="green"))
    else:
        print("\nSelect Option:")
        for opt, desc in options:
            print(f" [{opt}] {desc}")
        print()

def start_dashboard():
    print_header()
    if rich_available:
        console.print("[bold green]Starting Web Dashboard Flask server...[/bold green]")
        console.print("[yellow]Access the app at: http://localhost:5001[/yellow]")
        console.print("[bold red]Press Ctrl+C to stop the server and return to launcher menu.[/bold red]\n")
    else:
        print("Starting Web Dashboard Flask server...")
        print("Access the app at: http://localhost:5001")
        print("Press Ctrl+C to stop the server and return to launcher menu.\n")
        
    try:
        # Run Flask app as a subprocess
        subprocess.run([sys.executable, "modules/dashboard/app.py"])
    except KeyboardInterrupt:
        if rich_available:
            console.print("\n[bold yellow]Web Dashboard stopped.[/bold yellow]")
        else:
            print("\nWeb Dashboard stopped.")
    input("\nPress Enter to return to main menu...")

def scan_package():
    print_header()
    print("--- Scan Package (CLI Mode) ---\n")
    package = input("Enter package name (e.g. requests, lodash): ").strip()
    if not package:
        print("Package name cannot be empty.")
        input("Press Enter to return...")
        return
        
    ecosystem = input("Enter registry ecosystem (pypi/npm) [default: pypi]: ").strip().lower()
    if not ecosystem:
        ecosystem = "pypi"
    elif ecosystem not in ["pypi", "npm"]:
        print("Invalid ecosystem. Must be 'pypi' or 'npm'.")
        input("Press Enter to return...")
        return
        
    skip_dyn_in = input("Skip dynamic sandbox evaluation? (y/N): ").strip().lower()
    skip_dynamic = skip_dyn_in == 'y'
    
    save_rep_in = input("Save threat analysis report to a file? (Y/n): ").strip().lower()
    save_report = save_rep_in != 'n'
    
    output_path = None
    if save_report:
        output_path = input("Enter report output file path (e.g. audit_report.pdf, report.html, report.md) [default: audit_report.pdf]: ").strip()
        if not output_path:
            output_path = "audit_report.pdf"
            
    # Build CLI command
    cmd = [sys.executable, "depthcharge.py", "scan", package, "--type", ecosystem]
    if skip_dynamic:
        cmd.append("--skip-dynamic")
    if output_path:
        cmd.extend(["-o", output_path])
        
    print(f"\nExecuting scan command: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        
    input("\nPress Enter to return to main menu...")

def scan_file():
    print_header()
    print("--- Scan Dependency File ---\n")
    file_path = input("Enter path to file (e.g. test_requirements.txt, package.json): ").strip()
    if not file_path:
        print("File path cannot be empty.")
        input("Press Enter to return...")
        return
        
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        input("Press Enter to return...")
        return
        
    ecosystem = input("Default ecosystem if not auto-detected (pypi/npm) [default: pypi]: ").strip().lower()
    if not ecosystem:
        ecosystem = "pypi"
        
    skip_dyn_in = input("Skip dynamic sandbox evaluation? (y/N): ").strip().lower()
    skip_dynamic = skip_dyn_in == 'y'
    
    save_rep_in = input("Save threat analysis report to a file? (Y/n): ").strip().lower()
    save_report = save_rep_in != 'n'
    
    output_path = None
    if save_report:
        output_path = input("Enter report output file path (e.g. audit_report.pdf, report.html, report.md) [default: audit_report.pdf]: ").strip()
        if not output_path:
            output_path = "audit_report.pdf"
            
    # Build CLI command
    cmd = [sys.executable, "depthcharge.py", "scan-file", file_path, "--type", ecosystem]
    if skip_dynamic:
        cmd.append("--skip-dynamic")
    if output_path:
        cmd.extend(["-o", output_path])
        
    print(f"\nExecuting scan-file command: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        
    input("\nPress Enter to return to main menu...")

def view_history():
    print_header()
    print("--- Scan History ---\n")
    try:
        subprocess.run([sys.executable, "depthcharge.py", "history"])
    except KeyboardInterrupt:
        pass
    input("\nPress Enter to return to main menu...")

def main():
    while True:
        try:
            print_header()
            print_menu()
            choice = input("Enter choice (1-5): ").strip()
            if choice == "1":
                start_dashboard()
            elif choice == "2":
                scan_package()
            elif choice == "3":
                scan_file()
            elif choice == "4":
                view_history()
            elif choice == "5":
                print_header()
                if rich_available:
                    console.print("[bold cyan]Thank you for using Depthcharge! Safe coding![/bold cyan]")
                else:
                    print("Thank you for using Depthcharge! Safe coding!")
                break
            else:
                input("Invalid option. Press Enter to retry...")
        except KeyboardInterrupt:
            print_header()
            print("\nExiting launcher.")
            break

if __name__ == "__main__":
    main()
