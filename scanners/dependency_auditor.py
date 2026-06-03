#!/usr/bin/env python3
"""Dependency auditor that scans manifests, queries OSV.dev/NVD, and outputs SPDX SBOM."""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


MANIFEST_PARSERS = {}


def register_parser(name):
    """Decorator to register a manifest parser."""
    def decorator(func):
        MANIFEST_PARSERS[name] = func
        return func
    return decorator


def query_osv(package_name, package_version, ecosystem):
    """Query OSV.dev API for vulnerabilities."""
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": package_version,
    }).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError,
            TimeoutError, OSError) as e:
        return {"error": str(e)}


def query_nvd(cve_id):
    """Query NVD API for CVE details."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kirov-devsecops/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError,
            TimeoutError, OSError) as e:
        return {"error": str(e)}


def parse_requirement_spec(spec):
    """Parse a pip-style requirement specifier."""
    spec = spec.strip()
    if not spec or spec.startswith("#") or spec.startswith("-"):
        return None

    # Remove environment markers
    spec = re.split(r";\s*", spec)[0].strip()

    # Split operators
    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(([><=!~]+)\s*([\w.*-]+))?", spec)
    if not match:
        return None

    name = match.group(1).lower()
    operator = match.group(3) if match.group(2) else ">="
    version = match.group(4) if match.group(4) else "0.0.0"
    version = version.strip().lstrip("=vV")

    return {"name": name, "version": version, "operator": operator}


@register_parser("requirements.txt")
def parse_requirements_txt(path):
    """Parse pip requirements.txt."""
    deps = []
    if not path.exists():
        return deps
    with open(path) as f:
        for line in f:
            parsed = parse_requirement_spec(line)
            if parsed:
                deps.append(parsed)
    return deps


@register_parser("Pipfile")
def parse_pipfile(path):
    """Parse Pipfile for dependencies."""
    deps = []
    if not path.exists():
        return deps
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print("tomllib/tomli not available, trying pipfile-requirements")
            cmd = ["pipfile-requirements", str(path)]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parsed = parse_requirement_spec(line)
                        if parsed:
                            deps.append(parsed)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            return deps

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    for section in ("packages", "dev-packages"):
        for pkg_name, pkg_info in data.get(section, {}).items():
            if isinstance(pkg_info, str):
                version = pkg_info.strip("=").strip("\"")
            elif isinstance(pkg_info, dict):
                version = pkg_info.get("version", "*").strip("=").strip("\"")
            else:
                version = "*"
            deps.append({"name": pkg_name.lower(), "version": version, "operator": "=="})
    return deps


@register_parser("package.json")
def parse_package_json(path):
    """Parse npm package.json."""
    deps = []
    if not path.exists():
        return deps
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return deps

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg_name, version_spec in data.get(section, {}).items():
            version = version_spec.lstrip("~^>=<! ")
            deps.append({"name": pkg_name.lower(), "version": version, "operator": version_spec})
    return deps


@register_parser("go.mod")
def parse_go_mod(path):
    """Parse Go module dependencies."""
    deps = []
    if not path.exists():
        return deps
    with open(path) as f:
        content = f.read()

    lines = content.splitlines()
    in_require = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped.startswith(")"):
            in_require = False
            continue
        if in_require and stripped:
            parts = stripped.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                deps.append({"name": name, "version": version, "operator": "=="})
        elif stripped.startswith("require ") and not stripped.endswith("("):
            parts = stripped.split()
            if len(parts) >= 3:
                deps.append({"name": parts[1], "version": parts[2].lstrip("v"), "operator": "=="})
    return deps


ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
}


class DependencyAuditor:
    """Scans and audits dependencies against vulnerability databases."""

    def __init__(self, path="."):
        self.path = Path(path)
        self.manifest_deps = {}
        self.vulnerabilities = {}
        self.sbom_packages = []

    def find_manifests(self):
        """Find all supported manifest files."""
        manifests = {}
        manifest_names = [
            "requirements.txt", "Pipfile", "package.json", "go.mod",
            "requirements-dev.txt", "requirements-test.txt",
        ]
        for name in manifest_names:
            fp = self.path / name
            if fp.exists() and name in MANIFEST_PARSERS:
                manifests[name] = fp
        # Also search subdirectories
        for pattern in ["**/requirements.txt", "**/Pipfile", "**/package.json", "**/go.mod"]:
            for fp in self.path.glob(pattern):
                if fp.name not in manifests:
                    manifests[fp.name] = fp
        return manifests

    def parse_manifests(self):
        """Parse all discovered manifest files."""
        manifests = self.find_manifests()
        for name, fp in manifests.items():
            if name in MANIFEST_PARSERS:
                deps = MANIFEST_PARSERS[name](fp)
                if deps:
                    self.manifest_deps[str(fp.relative_to(self.path))] = {
                        "ecosystem": ECOSYSTEM_MAP.get(name, "Unknown"),
                        "dependencies": deps,
                    }
                    print(f"Parsed {len(deps)} deps from {fp.name}")
        return self.manifest_deps

    def audit_vulnerabilities(self, max_retries=2):
        """Cross-reference dependencies with OSV.dev."""
        for manifest_path, manifest_data in self.manifest_deps.items():
            ecosystem = manifest_data["ecosystem"]
            print(f"Auditing {len(manifest_data['dependencies'])} dependencies from {manifest_path}...")
            vulns = []
            for dep in manifest_data["dependencies"]:
                for attempt in range(max_retries):
                    try:
                        result = query_osv(dep["name"], dep["version"], ecosystem)
                        if "error" in result:
                            continue
                        vulns_list = result.get("vulns", [])
                        for vuln in vulns_list:
                            vuln_id = vuln.get("id", "UNKNOWN")
                            aliases = vuln.get("aliases", [])
                            cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                            vulns.append({
                                "vuln_id": vuln_id,
                                "cve_id": cve,
                                "package": dep["name"],
                                "version": dep["version"],
                                "ecosystem": ecosystem,
                                "summary": vuln.get("summary", ""),
                                "severity": self._infer_severity(vuln),
                                "cvss_score": self._get_cvss(vuln),
                                "fixed_version": self._get_fixed(vuln),
                                "references": vuln.get("references", []),
                                "manifest": manifest_path,
                            })
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            continue
                        print(f"  Error querying {dep['name']}: {e}", file=sys.stderr)

            self.vulnerabilities[manifest_path] = {
                "ecosystem": ecosystem,
                "vulnerabilities": vulns,
            }
            print(f"  Found {len(vulns)} vulnerabilities")
        return self.vulnerabilities

    def _infer_severity(self, vuln):
        """Infer severity from OSV database_specific or severity field."""
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity", "")
            if sev:
                return sev.upper()
        severity = vuln.get("severity", [])
        if severity:
            for s in severity:
                if isinstance(s, dict):
                    return s.get("type", "UNKNOWN")
        return "UNKNOWN"

    def _get_cvss(self, vuln):
        """Extract CVSS score from OSV response."""
        severity = vuln.get("severity", [])
        for s in severity:
            if isinstance(s, dict) and "score" in s:
                try:
                    return float(s["score"])
                except (ValueError, TypeError):
                    pass
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            for key in ("cvss_score", "cvss3_score", "cvss"):
                val = db_specific.get(key)
                if val:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
        return 0.0

    def _get_fixed(self, vuln):
        """Extract fixed version from OSV response."""
        affected = vuln.get("affected", [])
        for aff in affected:
            ranges = aff.get("ranges", [])
            for rng in ranges:
                events = rng.get("events", [])
                for evt in events:
                    if "fixed" in evt:
                        return evt["fixed"]
        return ""

    def build_dependency_tree(self):
        """Build a dependency tree with vulnerability annotations."""
        tree = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "manifests": {},
        }
        for manifest_path, manifest_data in self.manifest_deps.items():
            vulns_map = {}
            if manifest_path in self.vulnerabilities:
                for v in self.vulnerabilities[manifest_path]["vulnerabilities"]:
                    pkg = v["package"]
                    if pkg not in vulns_map:
                        vulns_map[pkg] = []
                    vulns_map[pkg].append(v)

            deps_tree = []
            for dep in manifest_data["dependencies"]:
                dep_vulns = vulns_map.get(dep["name"], [])
                deps_tree.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "operator": dep.get("operator", ">="),
                    "vulnerabilities": dep_vulns,
                    "vulnerable": len(dep_vulns) > 0,
                    "critical_count": sum(1 for v in dep_vulns
                                         if v.get("severity") == "CRITICAL"),
                    "high_count": sum(1 for v in dep_vulns
                                     if v.get("severity") == "HIGH"),
                })

            tree["manifests"][manifest_path] = {
                "ecosystem": manifest_data["ecosystem"],
                "dependencies": sorted(deps_tree, key=lambda d: -len(d["vulnerabilities"])),
            }
        return tree

    def generate_spdx_sbom(self):
        """Generate SPDX 2.3 SBOM."""
        spdx_id = "SPDXRef-DOCUMENT"
        doc_namespace = f"https://kirov.devsecops/sbom/{datetime.now().strftime('%Y%m%d%H%M%S')}"

        packages = []
        relationships = []
        pkg_counter = 0

        for manifest_path, manifest_data in self.manifest_deps.items():
            for dep in manifest_data["dependencies"]:
                pkg_counter += 1
                pkg_id = f"SPDXRef-Package-{pkg_counter}"
                pkg_name = dep["name"]
                pkg_version = dep["version"]

                # Compute package verification code (simplified)
                verif_code = hashlib.sha1(
                    f"{pkg_name}{pkg_version}".encode()
                ).hexdigest()

                packages.append({
                    "SPDXID": pkg_id,
                    "name": pkg_name,
                    "versionInfo": pkg_version,
                    "supplier": f"Organization: {manifest_data['ecosystem']}",
                    "downloadLocation": f"https://{manifest_data['ecosystem'].lower()}.com/{pkg_name}",
                    "filesAnalyzed": False,
                    "packageVerificationCode": {"packageVerificationCodeValue": verif_code},
                    "checksums": [],
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                })

                relationships.append({
                    "spdxElementId": spdx_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": pkg_id,
                })

                self.sbom_packages.append({
                    "name": pkg_name,
                    "version": pkg_version,
                    "spdx_id": pkg_id,
                })

        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_id,
            "name": "kirov-devsecops-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "creators": ["Tool: kirov-devsecops-suite-1.0"],
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "packages": packages,
            "relationships": relationships,
        }
        return sbom

    def generate_summary(self):
        """Generate an audit summary report."""
        total_deps = sum(
            len(d["dependencies"])
            for d in self.manifest_deps.values()
        )
        total_vulns = sum(
            len(v["vulnerabilities"])
            for v in self.vulnerabilities.values()
        )
        vuln_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        vuln_by_ecosystem = {}

        for manifest_path, vdata in self.vulnerabilities.items():
            eco = vdata["ecosystem"]
            if eco not in vuln_by_ecosystem:
                vuln_by_ecosystem[eco] = 0
            vuln_by_ecosystem[eco] += len(vdata["vulnerabilities"])

            for v in vdata["vulnerabilities"]:
                sev = v.get("severity", "UNKNOWN").upper()
                vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

        return {
            "generated": datetime.now(timezone.utc).isoformat(),
            "scan_path": str(self.path.absolute()),
            "total_manifests": len(self.manifest_deps),
            "total_dependencies": total_deps,
            "total_vulnerabilities": total_vulns,
            "vulnerabilities_by_severity": vuln_by_severity,
            "vulnerabilities_by_ecosystem": vuln_by_ecosystem,
            "manifests": list(self.manifest_deps.keys()),
        }


def main():
    parser = argparse.ArgumentParser(
        description="Dependency auditor with OSV.dev/NVD integration and SPDX SBOM output"
    )
    parser.add_argument("path", nargs="?", default=".",
                       help="Path to scan (default: current directory)")
    parser.add_argument(
        "--output-dir", default="dep-results",
        help="Output directory for results"
    )
    parser.add_argument(
        "--format", choices=["json", "csv", "spdx", "all"], default="all",
        help="Output format (default: all)"
    )
    parser.add_argument(
        "--skip-audit", action="store_true",
        help="Skip vulnerability audit (just parse manifests and generate SBOM)"
    )
    parser.add_argument(
        "--severity-threshold", default="HIGH",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to report (default: HIGH)"
    )
    args = parser.parse_args()

    auditor = DependencyAuditor(args.path)

    # Parse manifests
    auditor.parse_manifests()
    if not auditor.manifest_deps:
        print("No supported manifest files found", file=sys.stderr)
        sys.exit(0)

    # Audit vulnerabilities
    if not args.skip_audit:
        auditor.audit_vulnerabilities()
    else:
        auditor.vulnerabilities = {
            mp: {"ecosystem": md["ecosystem"], "vulnerabilities": []}
            for mp, md in auditor.manifest_deps.items()
        }

    # Build dependency tree
    tree = auditor.build_dependency_tree()

    # Generate SPDX SBOM
    spdx = auditor.generate_spdx_sbom()

    # Generate summary
    summary = auditor.generate_summary()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write outputs
    sev_threshold = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    if args.format in ("json", "all"):
        report_path = output_dir / "dependency-audit-report.json"
        with open(report_path, "w") as f:
            json.dump({
                "summary": summary,
                "dependency_tree": tree,
                "vulnerabilities": auditor.vulnerabilities,
            }, f, indent=2, default=str)
        print(f"JSON report: {report_path}")

    if args.format in ("csv", "all"):
        csv_path = output_dir / "dependency-audit.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Manifest", "Ecosystem", "Package", "Version",
                           "Vuln ID", "CVE ID", "Severity", "CVSS", "Fixed Version"])
            for mpath, vdata in auditor.vulnerabilities.items():
                for v in vdata["vulnerabilities"]:
                    writer.writerow([
                        mpath, vdata["ecosystem"], v["package"], v["version"],
                        v["vuln_id"], v["cve_id"], v["severity"],
                        v["cvss_score"], v["fixed_version"],
                    ])
        print(f"CSV report: {csv_path}")

    if args.format in ("spdx", "all"):
        spdx_path = output_dir / "sbom-spdx.json"
        with open(spdx_path, "w") as f:
            json.dump(spdx, f, indent=2)
        print(f"SPDX SBOM: {spdx_path}")

    # Print summary
    print(f"\n=== DEPENDENCY AUDIT SUMMARY ===")
    print(f"Manifests: {summary['total_manifests']}")
    print(f"Dependencies: {summary['total_dependencies']}")
    print(f"Vulnerabilities: {summary['total_vulnerabilities']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary["vulnerabilities_by_severity"].get(sev, 0)
        if count > 0:
            print(f"  {sev}: {count}")
    for eco, count in summary.get("vulnerabilities_by_ecosystem", {}).items():
        print(f"  {eco}: {count}")

    # Exit code based on threshold
    threshold_val = sev_threshold.get(args.severity_threshold, 3)
    for sev, val in [("CRITICAL", 4), ("HIGH", 3)]:
        if val <= threshold_val and summary["vulnerabilities_by_severity"].get(sev, 0) > 0:
            sys.exit(2)
    if threshold_val <= 3 and summary["total_vulnerabilities"] > 20:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
