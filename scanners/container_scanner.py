#!/usr/bin/env python3
"""Container vulnerability scanner with SARIF output."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


SARIF_TEMPLATE = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/openc2-schema/master/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "", "version": "", "informationUri": ""}},
        "results": [],
        "artifacts": [],
        "columnKind": "utf16CodeUnits",
    }],
}


def run_command(cmd, timeout=300):
    """Run a shell command and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout}s: {' '.join(cmd)}", file=sys.stderr)
        return "", "Timeout", -1
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}", file=sys.stderr)
        return "", "Not found", -1


class ContainerScanner:
    """Scans container images for vulnerabilities using Trivy and Grype."""

    def __init__(self, image, timeout=300):
        self.image = image
        self.timeout = timeout
        self.trivy_results = None
        self.grype_results = None
        self.pulled = False

    def pull_image(self):
        """Pull the Docker image."""
        print(f"Pulling image: {self.image}")
        stdout, stderr, rc = run_command(
            ["docker", "pull", self.image], self.timeout
        )
        if rc != 0:
            print(f"Failed to pull image: {stderr}", file=sys.stderr)
            return False
        self.pulled = True
        print(f"Successfully pulled {self.image}")
        return True

    def run_trivy_scan(self, severity="HIGH,CRITICAL"):
        """Run Trivy vulnerability scan."""
        print(f"Running Trivy scan on {self.image}...")
        stdout, stderr, rc = run_command([
            "trivy", "image",
            "--severity", severity,
            "--no-progress",
            "--format", "json",
            self.image,
        ], self.timeout)

        if rc != 0 and rc != 3:
            # Trivy returns exit code 1 for vulns found, 3 for errors
            if stderr and "not exist" in stderr.lower():
                print(f"Image {self.image} not found in local registry", file=sys.stderr)
            else:
                print(f"Trivy scan warning: {stderr}", file=sys.stderr)

        try:
            self.trivy_results = json.loads(stdout)
        except json.JSONDecodeError:
            print("Failed to parse Trivy JSON output", file=sys.stderr)
            self.trivy_results = {"Results": []}

        return self.trivy_results

    def run_grype_scan(self):
        """Run Grype vulnerability scan."""
        print(f"Running Grype scan on {self.image}...")
        stdout, stderr, rc = run_command([
            "grype", self.image,
            "-o", "json",
            "--fail-on", "high",
        ], self.timeout)

        try:
            self.grype_results = json.loads(stdout)
        except json.JSONDecodeError:
            print("Failed to parse Grype JSON output", file=sys.stderr)
            self.grype_results = {"matches": []}

        return self.grype_results

    def parse_trivy_results(self):
        """Parse Trivy results into structured format."""
        if not self.trivy_results:
            return []

        parsed = []
        for result in self.trivy_results.get("Results", []):
            target = result.get("Target", "unknown")
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                parsed.append({
                    "scanner": "trivy",
                    "target": target,
                    "vuln_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "package": vuln.get("PkgName", "unknown"),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "cvss_score": self._extract_cvss(vuln),
                    "published_date": vuln.get("PublishedDate", ""),
                    "url": f"https://avd.aquasec.com/nvd/{vuln.get('VulnerabilityID', '')}",
                })
        return parsed

    def parse_grype_results(self):
        """Parse Grype results into structured format."""
        if not self.grype_results:
            return []

        parsed = []
        for match in self.grype_results.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            cvss_data = self._extract_grype_cvss(vuln)
            parsed.append({
                "scanner": "grype",
                "target": artifact.get("name", "unknown"),
                "vuln_id": vuln.get("id", "UNKNOWN"),
                "package": artifact.get("name", "unknown"),
                "installed_version": artifact.get("version", ""),
                "fixed_version": self._get_fixed_version(match),
                "severity": vuln.get("severity", "Unknown"),
                "title": vuln.get("description", ""),
                "description": vuln.get("description", ""),
                "cvss_score": cvss_data.get("score", 0.0),
                "published_date": vuln.get("published", ""),
                "url": vuln.get("dataSource", ""),
            })
        return parsed

    def _extract_cvss(self, vuln):
        """Extract CVSS score from Trivy vulnerability."""
        for key in ["CVSS", "CvssScore"]:
            if key in vuln:
                cvss = vuln[key]
                if isinstance(cvss, dict):
                    for source, data in cvss.items():
                        if isinstance(data, dict):
                            return data.get("V3Score", data.get("V2Score", 0.0))
                    return 0.0
                try:
                    return float(cvss)
                except (ValueError, TypeError):
                    return 0.0
        # Try nvd-cvss scores
        nvd = vuln.get("NvdCvss", {})
        return nvd.get("V3Score", nvd.get("V2Score", 0.0))

    def _extract_grype_cvss(self, vuln):
        """Extract CVSS from Grype vulnerability."""
        cvss = vuln.get("cvss", [])
        if cvss:
            for entry in cvss:
                if isinstance(entry, dict):
                    metrics = entry.get("metrics", {})
                    score = metrics.get("baseScore", metrics.get("exploitabilityScore", 0))
                    return {"score": score, "vector": metrics.get("attackVector", "")}
        return {"score": 0.0, "vector": ""}

    def _get_fixed_version(self, match):
        """Extract fixed version from Grype match."""
        fix = match.get("fix", {})
        if fix.get("state") == "fixed":
            versions = fix.get("versions", [])
            return versions[0] if versions else ""
        return ""

    def generate_sarif(self, all_vulns, tool_name="KirovContainerScanner"):
        """Generate SARIF output from parsed vulnerabilities."""
        sarif = json.loads(json.dumps(SARIF_TEMPLATE))
        run = sarif["runs"][0]
        run["tool"]["driver"]["name"] = tool_name
        run["tool"]["driver"]["version"] = "1.0.0"
        run["tool"]["driver"]["informationUri"] = (
            "https://github.com/kirov/kirov-devsecops-suite"
        )

        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "UNKNOWN": "none",
        }

        for vuln in all_vulns:
            level = severity_map.get(vuln["severity"].upper(), "none")

            result = {
                "ruleId": vuln["vuln_id"],
                "level": level,
                "message": {
                    "text": f"{vuln['vuln_id']} in {vuln['package']}: "
                            f"{vuln['title'] or vuln['description'][:200]}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vuln["target"],
                            "description": {"text": f"Package: {vuln['package']}"}
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                            "message": {
                                "text": f"{vuln['package']} "
                                        f"{vuln['installed_version']} "
                                        f"(fixed: {vuln['fixed_version']})"
                            }
                        }
                    }
                }],
                "properties": {
                    "severity": vuln["severity"],
                    "cvss_score": vuln["cvss_score"],
                    "installed_version": vuln["installed_version"],
                    "fixed_version": vuln["fixed_version"],
                    "scanner": vuln["scanner"],
                    "published_date": vuln["published_date"],
                },
            }
            run["results"].append(result)

        return sarif

    def generate_summary_report(self, all_vulns):
        """Generate a summary report in JSON format."""
        summary = {
            "image": self.image,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_vulnerabilities": len(all_vulns),
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_vulnerabilities": [],
            "fixable_count": 0,
        }

        for vuln in all_vulns:
            sev = vuln["severity"].upper()
            if sev in summary["severity_counts"]:
                summary["severity_counts"][sev] += 1
            else:
                summary["severity_counts"][sev] = 1

            if vuln["fixed_version"]:
                summary["fixable_count"] += 1

        # Top 10 most severe
        sorted_vulns = sorted(
            all_vulns,
            key=lambda v: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(
                v["severity"].upper()) if v["severity"].upper()
                in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else 99, -v["cvss_score"])
        )
        summary["top_vulnerabilities"] = sorted_vulns[:10]

        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Container vulnerability scanner with SARIF output"
    )
    parser.add_argument("image", help="Docker image to scan (e.g., alpine:latest)")
    parser.add_argument(
        "--severity", default="HIGH,CRITICAL",
        help="Severity threshold (default: HIGH,CRITICAL)"
    )
    parser.add_argument(
        "--output-dir", default="scan-results",
        help="Output directory for scan results"
    )
    parser.add_argument(
        "--skip-pull", action="store_true",
        help="Skip pulling the image (assume already pulled)"
    )
    parser.add_argument(
        "--scanner", choices=["trivy", "grype", "both"], default="both",
        help="Scanner to use (default: both)"
    )
    args = parser.parse_args()

    scanner = ContainerScanner(args.image)

    if not args.skip_pull:
        if not scanner.pull_image():
            # Try without pulling if image exists locally
            print("Attempting to scan without explicit pull...")

    # Run selected scanners
    all_vulns = []

    if args.scanner in ("trivy", "both"):
        scanner.run_trivy_scan(args.severity)
        trivy_vulns = scanner.parse_trivy_results()
        print(f"Trivy found {len(trivy_vulns)} vulnerabilities")
        all_vulns.extend(trivy_vulns)

    if args.scanner in ("grype", "both"):
        scanner.run_grype_scan()
        grype_vulns = scanner.parse_grype_results()
        print(f"Grype found {len(grype_vulns)} vulnerabilities")
        all_vulns.extend(grype_vulns)

    # Deduplicate by vuln_id + package
    seen = set()
    unique_vulns = []
    for v in all_vulns:
        key = (v["vuln_id"], v["package"])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    all_vulns = unique_vulns

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate and save SARIF
    sarif = scanner.generate_sarif(all_vulns)
    sarif_path = output_dir / "container-scan-results.sarif"
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"SARIF output written to {sarif_path}")

    # Generate and save summary report
    summary = scanner.generate_summary_report(all_vulns)
    report_path = output_dir / "container-scan-report.json"
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"Summary report written to {report_path}")

    # Print summary to stdout
    print("\n=== SCAN SUMMARY ===")
    print(f"Image: {args.image}")
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    for severity, count in summary["severity_counts"].items():
        print(f"  {severity}: {count}")
    print(f"Fixable: {summary['fixable_count']}")

    # Exit code based on critical/high findings
    if summary["severity_counts"].get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif summary["severity_counts"].get("HIGH", 0) > 5:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
