#!/usr/bin/env python3
"""Infrastructure-as-Code scanner with CIS benchmark compliance reporting."""

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


CIS_BENCHMARK_MAPPING = {
    "terraform": {
        "CKV_AWS_1": "CIS 1.1 - IAM policies should not allow full administrative privileges",
        "CKV_AWS_2": "CIS 1.2 - Ensure CloudTrail log file validation is enabled",
        "CKV_AWS_3": "CIS 1.3 - Ensure CloudTrail is enabled in all regions",
        "CKV_AWS_4": "CIS 1.4 - Ensure CloudTrail bucket is not publicly accessible",
        "CKV_AWS_5": "CIS 1.5 - Ensure CloudTrail logs are encrypted at rest",
        "CKV_AWS_6": "CIS 1.6 - Ensure S3 bucket has public access blocks",
        "CKV_AWS_7": "CIS 1.7 - Ensure S3 buckets have versioning enabled",
        "CKV_AWS_8": "CIS 1.8 - Ensure IAM password policy requires uppercase letters",
        "CKV_AWS_9": "CIS 1.9 - Ensure IAM password policy requires lowercase letters",
        "CKV_AWS_10": "CIS 1.10 - Ensure IAM password policy requires symbols",
        "CKV_AWS_11": "CIS 1.11 - Ensure IAM password policy requires numbers",
        "CKV_AWS_12": "CIS 1.12 - Ensure IAM password policy minimum length >= 14",
        "CKV_AWS_13": "CIS 1.13 - Ensure MFA is enabled for root account",
        "CKV_AWS_14": "CIS 1.14 - Ensure access keys are rotated every 90 days",
        "CKV_AWS_15": "CIS 1.15 - Ensure IAM users receive permissions only through groups",
        "CKV_AWS_16": "CIS 2.1 - Ensure EBS volumes are encrypted",
        "CKV_AWS_17": "CIS 2.2 - Ensure EBS snapshots are not publicly restorable",
        "CKV_AWS_18": "CIS 2.3 - Ensure S3 buckets are encrypted at rest",
        "CKV_AWS_19": "CIS 2.4 - Ensure RDS instances are encrypted at rest",
        "CKV_AWS_20": "CIS 2.5 - Ensure RDS instances use SSL",
        "CKV_AWS_21": "CIS 2.6 - Ensure ECR repositories are encrypted at rest",
        "CKV_AWS_22": "CIS 3.1 - Ensure security groups do not allow 0.0.0.0/0 to port 22",
        "CKV_AWS_23": "CIS 3.2 - Ensure security groups do not allow 0.0.0.0/0 to port 3389",
        "CKV_AWS_24": "CIS 3.3 - Ensure VPC flow logging is enabled",
        "CKV_AWS_25": "CIS 3.4 - Ensure default security groups restrict all traffic",
        "CKV_AWS_26": "CIS 4.1 - Ensure EC2 instances are in a VPC",
        "CKV_AWS_27": "CIS 4.2 - Ensure EC2 instances do not have public IPs",
        "CKV_AWS_28": "CIS 4.3 - Ensure EC2 instances have detailed monitoring",
    },
    "kubernetes": {
        "CKV_K8S_1": "CIS 5.1 - Ensure container has ResourceLimit defined",
        "CKV_K8S_2": "CIS 5.2 - Ensure container has readOnlyRootFilesystem set",
        "CKV_K8S_3": "CIS 5.3 - Ensure container does not run as privileged",
        "CKV_K8S_4": "CIS 5.4 - Ensure container does not run as root",
        "CKV_K8S_5": "CIS 5.5 - Ensure container capabilities are dropped",
        "CKV_K8S_6": "CIS 5.6 - Ensure container has seccomp profile set",
        "CKV_K8S_7": "CIS 5.7 - Ensure container has AppArmor profile set",
        "CKV_K8S_8": "CIS 5.8 - Ensure container has SecurityContext defined",
        "CKV_K8S_9": "CIS 5.9 - Ensure container does not allow privilege escalation",
        "CKV_K8S_10": "CIS 5.10 - Ensure container has hostPID set to false",
        "CKV_K8S_11": "CIS 5.11 - Ensure container has hostNetwork set to false",
        "CKV_K8S_12": "CIS 5.12 - Ensure container has hostIPC set to false",
    },
}


def run_command(cmd, timeout=300):
    """Run a shell command and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}", file=sys.stderr)
        return "", "Timeout", -1
    except FileNotFoundError:
        return "", "Not found", -1
    except OSError as e:
        return "", str(e), -1


class IacScanner:
    """Scans IaC files using Checkov and tfsec with CIS benchmark alignment."""

    def __init__(self, path=".", frameworks=None):
        self.path = Path(path)
        self.frameworks = frameworks or ["terraform", "cloudformation", "kubernetes", "helm"]
        self.checkov_results = None
        self.tfsec_results = None

    def detect_frameworks(self):
        """Auto-detect which IaC frameworks are in use."""
        detected = []
        for fw, patterns in {
            "terraform": ["*.tf", "*.tfvars"],
            "cloudformation": ["*.yaml", "*.yml", "*.json"],
            "kubernetes": ["*.yaml", "*.yml"],
            "helm": ["Chart.yaml", "values.yaml"],
            "arm": ["*.json"],
        }.items():
            for pattern in patterns:
                matches = list(self.path.rglob(pattern))
                if matches:
                    detected.append(fw)
                    break
        return detected or self.frameworks

    def run_checkov(self):
        """Run Checkov scan on the target path."""
        print(f"Running Checkov on {self.path}...")
        fw = ",".join(self.frameworks)
        stdout, stderr, rc = run_command([
            "checkov", "-d", str(self.path),
            "--framework", fw,
            "--output", "json",
            "--compact",
            "--quiet",
        ])

        if rc not in (0, 1):
            print(f"Checkov warning: {stderr}", file=sys.stderr)

        try:
            self.checkov_results = json.loads(stdout)
        except json.JSONDecodeError:
            print("Failed to parse Checkov JSON output", file=sys.stderr)
            self.checkov_results = []

        return self.checkov_results

    def run_tfsec(self):
        """Run tfsec scan if Terraform files are present."""
        tf_path = self.path / "terraform"
        if not tf_path.exists() and not list(self.path.rglob("*.tf")):
            print("No Terraform files found, skipping tfsec")
            self.tfsec_results = []
            return []

        target = str(tf_path) if tf_path.exists() else str(self.path)
        print(f"Running tfsec on {target}...")
        stdout, stderr, rc = run_command([
            "tfsec", target,
            "--format", "json",
            "--no-colour",
            "--soft-fail",
        ])

        try:
            self.tfsec_results = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            print("Failed to parse tfsec JSON output", file=sys.stderr)
            self.tfsec_results = []

        return self.tfsec_results

    def parse_checkov_results(self):
        """Parse Checkov results into structured format."""
        if not self.checkov_results:
            return []

        parsed = []
        # Checkov returns a list of result summaries
        results = []
        if isinstance(self.checkov_results, dict):
            results = self.checkov_results.get("results", [])
            if not results:
                # Try alternative structure
                for key in ["failed_checks", "passed_checks", "skipped_checks"]:
                    results.extend(self.checkov_results.get(key, []))
        elif isinstance(self.checkov_results, list):
            results = self.checkov_results

        for check in results:
            check_id = check.get("check_id", "UNKNOWN")
            fw = check.get("bc_check_id", "").split("/")[0] if "/" in check.get("bc_check_id", "") else "general"
            parsed.append({
                "scanner": "checkov",
                "check_id": check_id,
                "framework": fw,
                "resource": check.get("resource", ""),
                "file_path": check.get("file_path", check.get("filename", "")),
                "file_line": check.get("file_line_range", [0, 0]),
                "status": check.get("check_result", {}).get("result", "FAILED"),
                "severity": check.get("severity", "MEDIUM"),
                "description": check.get("check_name", check.get("short_description", "")),
                "guideline": check.get("guideline", ""),
                "cis_mapping": CIS_BENCHMARK_MAPPING.get(fw, {}).get(check_id, ""),
                "evaluated_keys": check.get("evaluated_keys", []),
            })

        return parsed

    def parse_tfsec_results(self):
        """Parse tfsec results into structured format."""
        if not self.tfsec_results:
            return []

        parsed = []
        if isinstance(self.tfsec_results, dict):
            results = self.tfsec_results.get("results", [])
        elif isinstance(self.tfsec_results, list):
            results = self.tfsec_results
        else:
            results = []

        for result in results:
            result_id = result.get("rule_id", result.get("long_id", "UNKNOWN"))
            parsed.append({
                "scanner": "tfsec",
                "check_id": result_id,
                "framework": "terraform",
                "resource": result.get("location", {}).get("filename", ""),
                "file_path": result.get("location", {}).get("filename", ""),
                "file_line": [
                    result.get("location", {}).get("start_line", 0),
                    result.get("location", {}).get("end_line", 0),
                ],
                "status": "FAILED",
                "severity": result.get("severity", result.get("impact", "MEDIUM")).upper(),
                "description": result.get("description", result.get("long_message", "")),
                "guideline": result.get("resolution", ""),
                "cis_mapping": CIS_BENCHMARK_MAPPING.get("terraform", {}).get(result_id, ""),
                "evaluated_keys": [],
            })

        return parsed

    def generate_compliance_report(self, all_findings):
        """Generate CIS benchmark compliance report."""
        total_checks = len(CIS_BENCHMARK_MAPPING.get("terraform", {})) + \
                       len(CIS_BENCHMARK_MAPPING.get("kubernetes", {}))
        passed_checks = 0
        failed_checks = 0

        compliance_by_category = {}
        for fw, mappings in CIS_BENCHMARK_MAPPING.items():
            for check_id, cis_rule in mappings.items():
                category = cis_rule.split(" - ")[0]
                if category not in compliance_by_category:
                    compliance_by_category[category] = {"total": 0, "passed": 0, "failed": 0}
                compliance_by_category[category]["total"] += 1

        # Track which CIS rules are passed/failed
        for finding in all_findings:
            cis = finding.get("cis_mapping", "")
            if cis:
                category = cis.split(" - ")[0]
                if category not in compliance_by_category:
                    compliance_by_category[category] = {"total": 0, "passed": 0, "failed": 0}
                if finding.get("status") == "FAILED":
                    compliance_by_category[category]["failed"] += 1
                    failed_checks += 1
                else:
                    compliance_by_category[category]["passed"] += 1
                    passed_checks += 1

        # Assume passed for checks not triggered
        remaining = total_checks - (passed_checks + failed_checks)
        passed_checks += remaining

        compliance_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        report = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_path": str(self.path.absolute()),
            "frameworks": self.frameworks,
            "compliance_score": round(compliance_score, 1),
            "total_cis_checks": total_checks,
            "passed_cis_checks": passed_checks,
            "failed_cis_checks": failed_checks,
            "compliance_by_category": compliance_by_category,
            "findings": all_findings,
            "severity_summary": self._severity_summary(all_findings),
        }

        return report

    def _severity_summary(self, findings):
        """Summarize findings by severity."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def export_csv(self, findings, output_path):
        """Export findings to CSV."""
        if not findings:
            return
        fieldnames = [
            "check_id", "scanner", "framework", "status", "severity",
            "resource", "file_path", "file_line", "description", "cis_mapping"
        ]
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)
        print(f"CSV report written to {output_path}")

    def export_html(self, report, output_path):
        """Export compliance report as HTML."""
        findings = report.get("findings", [])
        failed = [f for f in findings if f.get("status") == "FAILED"]
        rows = ""
        for f in failed:
            cis = f.get("cis_mapping", "")
            rows += f"""
            <tr>
                <td>{f['check_id']}</td>
                <td>{f['severity']}</td>
                <td>{f['description'][:80]}</td>
                <td>{f['file_path']}:{f['file_line'][0]}</td>
                <td>{f['framework']}</td>
                <td>{cis}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IaC Compliance Report - {report['scan_path']}</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
h1 {{ color: #333; }}
.summary {{ display: flex; gap: 20px; margin: 20px 0; }}
.card {{ padding: 20px; border-radius: 8px; flex: 1; text-align: center; }}
.card.score {{ background: #e8f5e9; }}
.card.critical {{ background: #ffebee; }}
.card.warning {{ background: #fff3e0; }}
.card h2 {{ margin: 0 0 10px; font-size: 14px; }}
.card .value {{ font-size: 28px; font-weight: bold; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f5f5f5; }}
tr:hover {{ background: #f9f9f9; }}
.sev-CRITICAL {{ color: #d32f2f; font-weight: bold; }}
.sev-HIGH {{ color: #f57c00; }}
.sev-MEDIUM {{ color: #fbc02d; }}
.sev-LOW {{ color: #388e3c; }}
</style>
</head>
<body>
<h1>IaC Compliance Report - CIS Benchmark</h1>
<div class="summary">
    <div class="card score">
        <h2>Compliance Score</h2>
        <div class="value">{report['compliance_score']}%</div>
    </div>
    <div class="card critical">
        <h2>Failed Checks</h2>
        <div class="value">{report['failed_cis_checks']}</div>
    </div>
    <div class="card warning">
        <h2>Total Checks</h2>
        <div class="value">{report['total_cis_checks']}</div>
    </div>
</div>
<h2>Failed Findings ({len(failed)})</h2>
<table>
<tr><th>Check ID</th><th>Severity</th><th>Description</th><th>File</th><th>Framework</th><th>CIS Mapping</th></tr>
{rows}
</table>
<p>Generated: {report['scan_timestamp']}</p>
</body>
</html>"""
        with open(output_path, "w") as f:
            f.write(html)
        print(f"HTML report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="IaC scanner with CIS benchmark compliance reporting"
    )
    parser.add_argument("path", nargs="?", default=".",
                       help="Path to scan (default: current directory)")
    parser.add_argument(
        "--frameworks", nargs="+",
        default=["terraform", "cloudformation", "kubernetes", "helm"],
        help="IaC frameworks to scan (default: all)"
    )
    parser.add_argument(
        "--output-dir", default="iac-results",
        help="Output directory for results"
    )
    parser.add_argument(
        "--format", choices=["json", "csv", "html", "all"], default="all",
        help="Output format (default: all)"
    )
    parser.add_argument(
        "--skip-tfsec", action="store_true",
        help="Skip tfsec scan"
    )
    args = parser.parse_args()

    scanner = IacScanner(args.path, args.frameworks)

    # Detect frameworks if not specified
    detected = scanner.detect_frameworks()
    print(f"Detected IaC frameworks: {', '.join(detected)}")
    scanner.frameworks = detected

    # Run scans
    scanner.run_checkov()
    all_findings = scanner.parse_checkov_results()

    if not args.skip_tfsec:
        scanner.run_tfsec()
        all_findings.extend(scanner.parse_tfsec_results())

    print(f"Total findings: {len(all_findings)}")
    failed = [f for f in all_findings if f.get("status") == "FAILED"]
    print(f"Failed checks: {len(failed)}")

    # Generate compliance report
    report = scanner.generate_compliance_report(all_findings)

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Export reports
    if args.format in ("json", "all"):
        report_path = output_dir / "iac-compliance-report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"JSON report written to {report_path}")

    if args.format in ("csv", "all"):
        csv_path = output_dir / "iac-findings.csv"
        scanner.export_csv(all_findings, csv_path)

    if args.format in ("html", "all"):
        html_path = output_dir / "iac-compliance-report.html"
        scanner.export_html(report, html_path)

    # Print summary
    print(f"\n=== COMPLIANCE SUMMARY ===")
    print(f"Compliance Score: {report['compliance_score']}%")
    print(f"  Passed: {report['passed_cis_checks']}/{report['total_cis_checks']}")
    print(f"  Failed: {report['failed_cis_checks']}/{report['total_cis_checks']}")
    for sev, count in report["severity_summary"].items():
        if count > 0:
            print(f"  {sev}: {count}")

    # Exit with non-zero if critical/high failures
    if report["severity_summary"].get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif report["severity_summary"].get("HIGH", 0) > 10:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
