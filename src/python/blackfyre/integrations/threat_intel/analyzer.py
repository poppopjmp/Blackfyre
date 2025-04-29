import json
import os
import hashlib
import datetime
import requests
from typing import Dict, List, Optional, Set, Union
from pathlib import Path
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class ThreatIntelligenceAnalyzer:
    """Analyze binaries for malicious indicators using threat intelligence"""
    
    def __init__(self, binary_context: BinaryContext, cache_dir: Optional[Path] = None):
        """Initialize the threat intelligence analyzer
        
        Args:
            binary_context: The BinaryContext to analyze
            cache_dir: Directory to cache threat intelligence data
        """
        self.binary_context = binary_context
        
        # Set cache directory
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "blackfyre" / "threat_intel"
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load threat intelligence data
        self.threat_data = self._load_threat_data()
        
    def _load_threat_data(self) -> Dict:
        """Load threat intelligence data from cache or default data
        
        Returns:
            Dictionary of threat intelligence data
        """
        cache_file = self.cache_dir / "threat_intel.json"
        
        # In a real implementation, we would:
        # 1. Check for a valid API key for a threat intel service
        # 2. Query the service for the latest data if the cache is stale
        # 3. Update the cache with fresh data
        
        # For this example implementation, we'll use sample data
        sample_data = {
            "hash_indicators": {
                # Some example malware hashes
                "0a73291ab5607aef7db23863cf8e72f55bcb3c273bb47f00edf011515aeb5894": {
                    "malware_family": "Emotet",
                    "threat_level": "high",
                    "description": "Banking trojan and malware distributor"
                }
            },
            "string_indicators": {
                # Common malware strings/patterns
                "4system32\\csrss.exe": {
                    "malware_family": "Generic",
                    "threat_level": "medium",
                    "description": "Path masquerading as legitimate Windows process"
                },
                "cmd.exe /c ping 127.0.0.1 -n": {
                    "malware_family": "Generic",
                    "threat_level": "low",
                    "description": "Common evasion technique using ping for delay"
                }
            },
            "import_indicators": {
                # Suspicious import combinations
                "kernel32.dll": {
                    "functions": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
                    "if_all": True,
                    "malware_family": "Generic",
                    "threat_level": "medium",
                    "description": "Process injection pattern"
                },
                "advapi32.dll": {
                    "functions": ["RegCreateKeyEx", "RegSetValueEx"],
                    "if_all": False,
                    "malware_family": "Generic",
                    "threat_level": "low",
                    "description": "Registry manipulation pattern"
                }
            },
            "url_patterns": [
                r"https?://[^/]+\.ru/[^\s]+",
                r"https?://[^/]+\.cn/[^\s]+",
                r"https?://(?:\d{1,3}\.){3}\d{1,3}/[^\s]+"
            ],
            "ip_patterns": [
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ],
            "data_source": "Sample data for demonstration",
            "version": "1.0"
        }
        
        # Create or update cache
        if not cache_file.exists():
            with open(cache_file, 'w') as f:
                json.dump(sample_data, f, indent=2)
                
        return sample_data
    
    def check_hash_indicators(self) -> List[Dict]:
        """Check binary hash against known malicious hashes
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check binary hash
        if self.binary_context.sha256_hash in self.threat_data["hash_indicators"]:
            indicator = self.threat_data["hash_indicators"][self.binary_context.sha256_hash]
            
            findings.append({
                "type": "binary_hash",
                "hash": self.binary_context.sha256_hash,
                "malware_family": indicator["malware_family"],
                "threat_level": indicator["threat_level"],
                "description": indicator["description"]
            })
            
        return findings
    
    def check_string_indicators(self) -> List[Dict]:
        """Check binary strings against known malicious patterns
        
        Returns:
            List of findings
        """
        import re
        findings = []
        
        # Check for known malicious strings
        for addr, string_val in self.binary_context.string_refs.items():
            # Check exact matches
            if string_val in self.threat_data["string_indicators"]:
                indicator = self.threat_data["string_indicators"][string_val]
                
                findings.append({
                    "type": "malicious_string",
                    "string": string_val,
                    "address": hex(addr),
                    "malware_family": indicator["malware_family"],
                    "threat_level": indicator["threat_level"],
                    "description": indicator["description"]
                })
            
            # Check for URL patterns
            for pattern in self.threat_data["url_patterns"]:
                if re.search(pattern, string_val):
                    findings.append({
                        "type": "suspicious_url",
                        "string": string_val,
                        "address": hex(addr),
                        "pattern": pattern,
                        "threat_level": "medium",
                        "description": "String contains suspicious URL pattern"
                    })
                    break
            
            # Check for IP patterns
            for pattern in self.threat_data["ip_patterns"]:
                if re.search(pattern, string_val):
                    findings.append({
                        "type": "potential_ip",
                        "string": string_val,
                        "address": hex(addr),
                        "pattern": pattern,
                        "threat_level": "low",
                        "description": "String contains potential IP address"
                    })
                    break
                    
        return findings
    
    def check_import_indicators(self) -> List[Dict]:
        """Check binary imports against suspicious patterns
        
        Returns:
            List of findings
        """
        findings = []
        
        # Group imports by library
        imports_by_library = {}
        for imp in self.binary_context.import_symbols:
            if imp.library_name not in imports_by_library:
                imports_by_library[imp.library_name] = []
            imports_by_library[imp.library_name].append(imp.name)
        
        # Check for suspicious import patterns
        for lib_name, indicator in self.threat_data["import_indicators"].items():
            if lib_name in imports_by_library:
                lib_imports = set(imports_by_library[lib_name])
                required_functions = set(indicator["functions"])
                
                if indicator["if_all"]:
                    # All functions must be present
                    if required_functions.issubset(lib_imports):
                        findings.append({
                            "type": "suspicious_imports",
                            "library": lib_name,
                            "imports": list(required_functions),
                            "malware_family": indicator["malware_family"],
                            "threat_level": indicator["threat_level"],
                            "description": indicator["description"]
                        })
                else:
                    # Any function match is sufficient
                    matching_imports = required_functions.intersection(lib_imports)
                    if matching_imports:
                        findings.append({
                            "type": "suspicious_imports",
                            "library": lib_name,
                            "imports": list(matching_imports),
                            "malware_family": indicator["malware_family"],
                            "threat_level": indicator["threat_level"],
                            "description": indicator["description"]
                        })
                        
        return findings
    
    def analyze(self) -> Dict:
        """Perform comprehensive threat analysis
        
        Returns:
            Analysis results
        """
        # Run all checks
        hash_findings = self.check_hash_indicators()
        string_findings = self.check_string_indicators()
        import_findings = self.check_import_indicators()
        
        # Combine findings
        all_findings = hash_findings + string_findings + import_findings
        
        # Calculate threat score (simple scoring based on finding counts and severity)
        threat_score = 0
        for finding in all_findings:
            if finding["threat_level"] == "high":
                threat_score += 10
            elif finding["threat_level"] == "medium":
                threat_score += 5
            elif finding["threat_level"] == "low":
                threat_score += 1
        
        # Determine overall threat assessment
        threat_assessment = "low"
        if threat_score >= 20:
            threat_assessment = "high"
        elif threat_score >= 10:
            threat_assessment = "medium"
        
        return {
            "binary": {
                "name": self.binary_context.name,
                "sha256": self.binary_context.sha256_hash
            },
            "findings": all_findings,
            "total_findings": len(all_findings),
            "threat_score": threat_score,
            "threat_assessment": threat_assessment,
            "findings_by_type": {
                "hash": len(hash_findings),
                "string": len(string_findings),
                "import": len(import_findings)
            }
        }
    
    def generate_stix(self) -> Dict:
        """Generate STIX 2.1 representation of findings
        
        Returns:
            STIX bundle as a dictionary
        """
        # This is a simplified STIX 2.1 implementation
        # In a real implementation, we would use a STIX library
        
        import uuid
        from datetime import datetime
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Create a STIX bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "objects": []
        }
        
        # Add binary as a malware object
        binary_object = {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{str(uuid.uuid4())}",
            "created": now,
            "modified": now,
            "name": self.binary_context.name,
            "description": f"Binary analyzed by Blackfyre",
            "is_family": False,
            "hashes": {
                "SHA-256": self.binary_context.sha256_hash
            }
        }
        bundle["objects"].append(binary_object)
        
        # Add indicators from findings
        analysis_results = self.analyze()
        for finding in analysis_results["findings"]:
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{str(uuid.uuid4())}",
                "created": now,
                "modified": now,
                "name": f"Blackfyre Detection: {finding['type']}",
                "description": finding["description"],
                "indicator_types": ["malicious-activity"],
                "pattern": "",
                "pattern_type": "stix",
                "valid_from": now
            }
            
            # Set pattern based on finding type
            if finding["type"] == "binary_hash":
                indicator["pattern"] = f"[file:hashes.'SHA-256' = '{finding['hash']}']"
            elif finding["type"] == "malicious_string":
                indicator["pattern"] = f"[file:contains_refs.string_value = '{finding['string']}']"
            elif finding["type"] == "suspicious_imports":
                patterns = []
                for imp in finding["imports"]:
                    patterns.append(f"file:extensions.windows-pebinary-ext.import_functions = '{imp}'")
                indicator["pattern"] = "[" + " AND ".join(patterns) + "]"
            
            bundle["objects"].append(indicator)
            
            # Add relationship
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{str(uuid.uuid4())}",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator["id"],
                "target_ref": binary_object["id"]
            }
            bundle["objects"].append(relationship)
        
        return bundle
    
    def generate_report(self, output_file: Optional[str] = None, include_stix: bool = False) -> str:
        """Generate a threat intelligence report
        
        Args:
            output_file: Optional path to write the report to
            include_stix: Whether to include STIX data
            
        Returns:
            The report as a string (markdown format)
        """
        analysis_results = self.analyze()
        
        # Generate markdown report
        report = f"""# Threat Intelligence Report

## Binary Information
- **Name:** {analysis_results['binary']['name']}
- **SHA-256:** {analysis_results['binary']['sha256']}

## Threat Assessment
- **Threat Score:** {analysis_results['threat_score']}
- **Overall Assessment:** {analysis_results['threat_assessment'].upper()}
- **Total Findings:** {analysis_results['total_findings']}

## Findings Summary
- Hash-based findings: {analysis_results['findings_by_type']['hash']}
- String-based findings: {analysis_results['findings_by_type']['string']}
- Import-based findings: {analysis_results['findings_by_type']['import']}

## Detailed Findings
"""
        
        # Add detailed findings
        for i, finding in enumerate(analysis_results['findings']):
            report += f"### {i+1}. {finding['description']}\n"
            report += f"- **Type:** {finding['type']}\n"
            report += f"- **Threat Level:** {finding['threat_level'].upper()}\n"
            
            if "malware_family" in finding:
                report += f"- **Malware Family:** {finding['malware_family']}\n"
                
            if finding['type'] == 'binary_hash':
                report += f"- **Hash:** {finding['hash']}\n"
            elif finding['type'] == 'malicious_string' or finding['type'] == 'suspicious_url' or finding['type'] == 'potential_ip':
                report += f"- **String:** {finding['string']}\n"
                report += f"- **Address:** {finding['address']}\n"
            elif finding['type'] == 'suspicious_imports':
                report += f"- **Library:** {finding['library']}\n"
                report += f"- **Functions:** {', '.join(finding['imports'])}\n"
                
            report += "\n"
        
        # Add STIX data if requested
        if include_stix:
            stix_data = self.generate_stix()
            report += "## STIX 2.1 Data\n\n```json\n"
            report += json.dumps(stix_data, indent=2)
            report += "\n```\n"
            
        # Write to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Threat intelligence report written to {output_file}")
            
            # Also write the STIX data to a separate file if requested
            if include_stix:
                stix_file = os.path.splitext(output_file)[0] + ".stix.json"
                with open(stix_file, 'w') as f:
                    json.dump(self.generate_stix(), f, indent=2)
                print(f"STIX data written to {stix_file}")
        
        return report
