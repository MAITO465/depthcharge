import re
with open("depthcharge.py", "r") as f:
    content = f.read()

# 1. Update run_scan signature
content = content.replace(
    'def run_scan(package_name, ecosystem="pypi", skip_dynamic=False):',
    'def run_scan(package_name, ecosystem="pypi", skip_reputation=False, skip_static=False, skip_dynamic=False):'
)

# 2. Inside run_scan, after rep_results = scan_reputation(...)
rep_patch = """        if not rep_results.get("exists"):"""
rep_replacement = """        if skip_reputation:
            if rich_available:
                console.print("[bold yellow]⚠ Reputation Scan skipped by request (metadata fetched only).[/bold yellow]")
            else:
                print("⚠ Reputation Scan skipped by request (metadata fetched only).")
            # Clear threat flags so score is 0
            rep_results["vulnerabilities"] = []
            rep_results["typosquatting_detected"] = False
            rep_results["is_suspiciously_new"] = False
            rep_results["known_malicious"] = False
            rep_results["malware_database_match"] = False
            
        if not rep_results.get("exists"):"""
content = content.replace(rep_patch, rep_replacement)

# 3. Inside run_scan, update static scan
static_patch = """        # 2. Static Scan
        download_url = rep_results.get("download_url")
        with console.status(f"[bold green]Running Static Scan for {package_name}...", spinner="dots"):
            static_results = scan_static(package_name, ecosystem, download_url)
            
        if static_results.get("error"):
            console.print(f"[bold yellow]⚠ Static Scan Warning:[/bold yellow] {static_results.get('error')}")
        else:
            console.print("[bold green]✓ Static Scan complete.[/bold green]")"""
            
static_replacement = """        # 2. Static Scan
        download_url = rep_results.get("download_url")
        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            with console.status(f"[bold green]Running Static Scan for {package_name}...", spinner="dots"):
                static_results = scan_static(package_name, ecosystem, download_url)
                
            if static_results.get("error"):
                console.print(f"[bold yellow]⚠ Static Scan Warning:[/bold yellow] {static_results.get('error')}")
            else:
                console.print("[bold green]✓ Static Scan complete.[/bold green]")
        else:
            console.print("[bold yellow]⚠ Static scan skipped by request.[/bold yellow]")"""
content = content.replace(static_patch, static_replacement)

# 4. Same for the non-rich fallback in run_scan
fallback_static = """        print("Running Static Scan...")
        static_results = scan_static(package_name, ecosystem, rep_results.get("download_url"))"""
        
fallback_static_repl = """        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            print("Running Static Scan...")
            static_results = scan_static(package_name, ecosystem, rep_results.get("download_url"))
        else:
            print("Static scan skipped by request.")"""
content = content.replace(fallback_static, fallback_static_repl)

# 5. Update scan_file signature
content = content.replace(
    'def scan_file(file_path, default_ecosystem="pypi", skip_dynamic=False):',
    'def scan_file(file_path, default_ecosystem="pypi", skip_reputation=False, skip_static=False, skip_dynamic=False):'
)

content = content.replace(
    'score_data = run_scan(package, ecosystem, skip_dynamic)',
    'score_data = run_scan(package, ecosystem, skip_reputation, skip_static, skip_dynamic)'
)

# 6. Update argparse
argparse_patch = """    scan_parser.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic sandbox evaluation")"""
argparse_repl = """    scan_parser.add_argument("--skip-reputation", action="store_true", help="Skip reputation scoring")
    scan_parser.add_argument("--skip-static", action="store_true", help="Skip static code analysis")
    scan_parser.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic sandbox evaluation")"""
content = content.replace(argparse_patch, argparse_repl)

file_argparse_patch = """    file_parser.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic sandbox evaluation")"""
file_argparse_repl = """    file_parser.add_argument("--skip-reputation", action="store_true", help="Skip reputation scoring")
    file_parser.add_argument("--skip-static", action="store_true", help="Skip static code analysis")
    file_parser.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic sandbox evaluation")"""
content = content.replace(file_argparse_patch, file_argparse_repl)

# 7. Update argparse parsing in command handlers
cmd_scan_call = """res = run_scan(args.package, args.type, args.skip_dynamic)"""
cmd_scan_call_repl = """res = run_scan(args.package, args.type, args.skip_reputation, args.skip_static, args.skip_dynamic)"""
content = content.replace(cmd_scan_call, cmd_scan_call_repl)

cmd_scanfile_call = """has_high_risk, results = scan_file(args.lockfile, args.type, args.skip_dynamic)"""
cmd_scanfile_call_repl = """has_high_risk, results = scan_file(args.lockfile, args.type, args.skip_reputation, args.skip_static, args.skip_dynamic)"""
content = content.replace(cmd_scanfile_call, cmd_scanfile_call_repl)

cmd_scanfile_call2 = """has_high_risk, results = scan_file(args.path, args.type, args.skip_dynamic)"""
cmd_scanfile_call2_repl = """has_high_risk, results = scan_file(args.path, args.type, args.skip_reputation, args.skip_static, args.skip_dynamic)"""
content = content.replace(cmd_scanfile_call2, cmd_scanfile_call2_repl)

with open("depthcharge.py", "w") as f:
    f.write(content)
print("depthcharge.py patched successfully!")
