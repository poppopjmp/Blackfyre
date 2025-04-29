import requests
import re
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class VulnerabilityMatcher:
    def __init__(self, binary_context: BinaryContext, cache_dir: Optional[Path] = None):
        """Initialize the vulnerability matcher
        
        Args:
            binary_context: The BinaryContext to check for vulnerabilities
            cache_dir: Directory to cache vulnerability data (default: ~/.cache/blackfyre/vulndb)
        """
        self.binary_context = binary_context
        
        # Set cache directory
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "blackfyre" / "vulndb"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load vulnerability database
        self.vulns = self._load_vuln_database()
        
    def _load_vuln_database(self) -> Dict[str, Any]:
        """Load the vulnerability database from cache or download it
        
        Returns:
            Dictionary of vulnerability data
        """
        cache_file = self.cache_dir / "vuln_db.json"
        
        # Use cached data if available and fresh (< 7 days old)
        if cache_file.exists():
            cache_age = (
                datetime.datetime.now() - datetime.datetime.fromtimestamp(cache_file.stat().st_mtime)
            )
            if cache_age.days < 7:
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except (json.JSONDecodeError, IOError):
                    pass  # Fall through to download
        
        # If not cached or cache is stale, download the database
        # In a real implementation, this would connect to a proper vulnerability database
        print("Downloading vulnerability database...")
        
        # This is a placeholder - in a real implementation, we would download from
        # an actual vulnerability database API
        
        # Simulate downloading and parsing vulnerability data
        # For this example, we'll use a small placeholder database
        vuln_data = {
            "functions": {
                "strcpy": {
                    "cve": "CVE-2019-12345",
                    "description": "Buffer overflow vulnerability in strcpy function",
                    "severity": "high",
                    "recommendations": ["Use strncpy or strlcpy instead"]
                },
                "gets": {
                    "cve": "CVE-2018-54321",
                    "description": "Buffer overflow vulnerability in gets function",
                    "severity": "critical",
                    "recommendations": ["Use fgets instead"]
                },
                "sprintf": {
                    "cve": "CVE-2017-98765",
                    "description": "Format string vulnerability in sprintf",
                    "severity": "medium",
                    "recommendations": ["Use snprintf instead"]
                }
            },
            "patterns": {
                "weak_encryption": {
                    "functions": ["DES_set_key", "RC4"],
                    "cve": "CVE-2016-45678",
                    "description": "Use of weak encryption algorithms",
                    "severity": "medium",
                    "recommendations": ["Use AES or ChaCha20 instead"]
                },
                "insecure_random": {
                    "functions": ["rand", "random", "srand"],
                    "cve": "CVE-2015-56789",
                    "description": "Use of insecure random number generators",
                    "severity": "medium",
                    "recommendations": ["Use secure random functions like /dev/urandom or CryptGenRandom"]
                }
            },
            "database_version": "1.0",
            "last_updated": "2023-01-01"
        }
        
        # Save to cache
        with open(cache_file, 'w') as f:
            json.dump(vuln_data, f, indent=2)
            
        return vuln_data
        
    def scan_binary(self) -> Dict[str, Any]:
        """Scan the binary for known vulnerabilities
        
        Returns:
            Dictionary of findings
        """
        findings = {
            "binary_name": self.binary_context.name,
            "binary_hash": self.binary_context.sha256_hash,
            "vulnerabilities": [],
            "warnings": []
        }
        
        # Check dangerous functions
        function_vulns = self._check_dangerous_functions()
        findings["vulnerabilities"].extend(function_vulns)
        
        # Check vulnerability patterns
        pattern_vulns = self._check_vulnerability_patterns()
        findings["vulnerabilities"].extend(pattern_vulns)
        
        # Summarize findings
        findings["total_vulnerabilities"] = len(findings["vulnerabilities"])
        findings["severity_counts"] = {
            "critical": sum(1 for v in findings["vulnerabilities"] if v.get("severity") == "critical"),
            "high": sum(1 for v in findings["vulnerabilities"] if v.get("severity") == "high"),
            "medium": sum(1 for v in findings["vulnerabilities"] if v.get("severity") == "medium"),
            "low": sum(1 for v in findings["vulnerabilities"] if v.get("severity") == "low")
        }
        
        return findings
    
    def _check_dangerous_functions(self) -> List[Dict[str, Any]]:
        """Check for known dangerous functions
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Check imports for known dangerous functions
        for import_sym in self.binary_context.import_symbols:
            # Check if the function name is in our vulnerability database
            func_name = import_sym.name.lower()
            
            if func_name in self.vulns["functions"]:
                vuln_info = self.vulns["functions"][func_name]
                
                finding = {
                    "type": "dangerous_function",
                    "function_name": import_sym.name,
                    "address": hex(import_sym.address),
                    "library": import_sym.library_name,
                    "cve": vuln_info.get("cve", ""),
                    "description": vuln_info.get("description", ""),
                    "severity": vuln_info.get("severity", ""),
                    "recommendations": vuln_info.get("recommendations", [])
                }
                
                findings.append(finding)
        
        return findings
    
    def _check_vulnerability_patterns(self) -> List[Dict[str, Any]]:
        """Check for vulnerability patterns
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # For each pattern in our database
        for pattern_name, pattern_info in self.vulns["patterns"].items():
            # Check if the binary matches the pattern
            matches = []
            
            # Check function patterns (simplistic approach)
            for func_name in pattern_info.get("functions", []):
                for import_sym in self.binary_context.import_symbols:
                    if func_name.lower() in import_sym.name.lower():
                        matches.append({
                            "function": import_sym.name,
                            "address": hex(import_sym.address),
                            "library": import_sym.library_name
                        })
            
            # If we found matches, add a finding
            if matches:
                finding = {
                    "type": "vulnerability_pattern",
                    "pattern_name": pattern_name,
                    "matches": matches,
                    "cve": pattern_info.get("cve", ""),
                    "description": pattern_info.get("description", ""),
                    "severity": pattern_info.get("severity", ""),
                    "recommendations": pattern_info.get("recommendations", [])
                }
                
                findings.append(finding)
        
        return findings
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate a vulnerability report
        
        Args:
            output_file: Optional path to write the report to
            
        Returns:
            The report as a string
        """
        findings = self.scan_binary()
        
        # Generate markdown report
        report = f"""# Vulnerability Analysis Report

## Binary Information
- **Name:** {findings['binary_name']}
- **SHA-256:** {findings['binary_hash']}
- **Architecture:** {self.binary_context.proc_type}
- **File Type:** {self.binary_context.file_type}

## Summary
- **Total Vulnerabilities:** {findings['total_vulnerabilities']}
- **Critical:** {findings['severity_counts']['critical']}
- **High:** {findings['severity_counts']['high']}
- **Medium:** {findings['severity_counts']['medium']}
- **Low:** {findings['severity_counts']['low']}

## Detailed Findings
"""
        
        # Add vulnerability details
        for i, vuln in enumerate(findings['vulnerabilities'], 1):
            report += f"### {i}. {vuln['description']}\n"
            report += f"- **Type:** {vuln['type']}\n"
            report += f"- **Severity:** {vuln['severity']}\n"
            
            if 'cve' in vuln and vuln['cve']:
                report += f"- **CVE:** {vuln['cve']}\n"
                
            if vuln['type'] == 'dangerous_function':
                report += f"- **Function:** {vuln['function_name']}\n"
                report += f"- **Library:** {vuln['library']}\n"
                report += f"- **Address:** {vuln['address']}\n"
            elif vuln['type'] == 'vulnerability_pattern':
                report += f"- **Pattern:** {vuln['pattern_name']}\n"
                report += "- **Matches:**\n"
                for match in vuln['matches']:
                    report += f"  - {match['function']} ({match['library']}) at {match['address']}\n"
            
            if 'recommendations' in vuln and vuln['recommendations']:
                report += "- **Recommendations:**\n"
                for rec in vuln['recommendations']:
                    report += f"  - {rec}\n"
                    
            report += "\n"
        
        # Write to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Vulnerability report written to {output_file}")
        
        return report
