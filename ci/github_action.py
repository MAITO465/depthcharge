import os
import sys
import json
import subprocess
import requests

def post_github_pr_comment(repo_name, pr_number, token, comment_body):
    url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {"body": comment_body}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=15)
        if r.status_code == 201:
            print("Successfully posted scan report comment to PR.")
        else:
            print(f"Failed to post PR comment: HTTP {r.status_code}. Response: {r.text}")
    except Exception as e:
        print(f"Error posting PR comment: {e}")

def main():
    print("--- DepthCharge CI/CD Pull Request Security Scan ---")
    
    # 1. Parse configuration from environment / inputs
    lockfile_path = os.environ.get("INPUT_LOCKFILE", "requirements.txt")
    threshold = int(os.environ.get("INPUT_THRESHOLD", "70"))
    fail_on_high = os.environ.get("INPUT_FAIL_ON_HIGH", "true").lower() == "true"
    output_path = os.environ.get("INPUT_OUTPUT")
    skip_dynamic = os.environ.get("INPUT_SKIP_DYNAMIC", "false").lower() == "true"
    
    print(f"Target Lockfile: {lockfile_path}")
    print(f"Risk Threshold: {threshold}")
    print(f"Fail on High: {fail_on_high}")
    if output_path:
        print(f"Main Output Path: {output_path}")
    print(f"Skip Dynamic Sandboxing: {skip_dynamic}")
    
    # 2. Run the depthcharge scan-file command
    # We output a Markdown report to /tmp/depthcharge_report.md
    report_md_path = "/tmp/depthcharge_report.md"
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    depthcharge_script = os.path.join(project_root, "depthcharge.py")
    
    main_output = output_path if output_path else "/tmp/depthcharge_report.html"
    
    cmd = [
        sys.executable, depthcharge_script,
        "scan-file", lockfile_path,
        "-o", main_output,
        "--markdown", report_md_path,
        "--threshold", str(threshold)
    ]
    if skip_dynamic:
        cmd.append("--skip-dynamic")
    if fail_on_high:
        cmd.append("--fail-on-high")
    
    # Run scanner
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print("Scan Execution Output:")
    print(res.stdout)
    if res.stderr:
        print("Scan Execution Errors:")
        print(res.stderr)
        
    # Check scan results
    scan_failed = res.returncode != 0
    
    # 3. Read Markdown report and post to PR
    markdown_report = ""
    if os.path.exists(report_md_path):
        with open(report_md_path, "r", encoding="utf-8") as f:
            markdown_report = f.read()
            
    # GitHub Action context details
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo_name = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
    
    if event_path and os.path.exists(event_path) and repo_name and token:
        try:
            with open(event_path, "r") as f:
                event_data = json.load(f)
            pr_number = event_data.get("pull_request", {}).get("number")
            
            if pr_number and markdown_report:
                # Prepend a header to the comment
                comment_body = f"## 🛡️ DepthCharge Supply Chain Scan Report\n\n{markdown_report}"
                post_github_pr_comment(repo_name, pr_number, token, comment_body)
            else:
                print("No Pull Request number found in event payload; skipping comment.")
        except Exception as e:
            print(f"Failed to parse GITHUB_EVENT_PATH: {e}")
    else:
        print("GitHub Actions PR event details or tokens are not present; skipping PR comment.")

    # Fail the step if scan failed and fail_on_high is configured
    if scan_failed and fail_on_high:
        print(f"FAIL: One or more package risk scores exceeded the threshold of {threshold}.")
        sys.exit(1)
    else:
        print("SUCCESS: Scan completed successfully or threshold failures ignored.")
        sys.exit(0)

if __name__ == "__main__":
    main()
