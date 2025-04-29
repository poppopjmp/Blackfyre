"""Mobile app package analyzer for Blackfyre"""

import os
import re
import json
import zipfile
import plistlib
import xml.etree.ElementTree as ET
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Iterator
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class AppPackageAnalyzer:
    """Analyzer for mobile app packages (APK, IPA)"""
    
    def __init__(self, 
                 package_path: str,
                 extraction_dir: Optional[str] = None):
        """Initialize the app package analyzer
        
        Args:
            package_path: Path to app package file
            extraction_dir: Directory to extract package contents
        """
        self.package_path = package_path
        
        # Validate package path
        if not os.path.exists(package_path):
            raise FileNotFoundError(f"Package file not found: {package_path}")
            
        # Determine package type based on extension
        self.package_type = os.path.splitext(package_path)[1].lower()
        if self.package_type not in ['.apk', '.ipa', '.xapk']:
            raise ValueError(f"Unsupported package type: {self.package_type}")
            
        # Set up extraction directory
        if extraction_dir:
            self.extraction_dir = Path(extraction_dir)
        else:
            # Default extraction directory next to package file
            parent = Path(package_path).parent
            base_name = Path(package_path).stem
            self.extraction_dir = parent / f"{base_name}_extracted"
            
        self.logger = logging.getLogger(__name__)
        
        # Analysis results
        self.package_info = {}
        self.manifest = {}
        self.files = []
        self.native_libraries = []
        self.permissions = []
        self.certificates = []
        self.strings = {}
        self.potential_issues = []
    
    def extract_package(self) -> List[str]:
        """Extract contents of app package
        
        Returns:
            List of extracted file paths
        """
        # Create extraction directory
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        extracted_files = []
        
        self.logger.info(f"Extracting {self.package_type} package: {self.package_path}")
        
        try:
            with zipfile.ZipFile(self.package_path, 'r') as zip_ref:
                # Extract all files
                for file_info in zip_ref.infolist():
                    if not file_info.is_dir():
                        extracted_path = os.path.join(self.extraction_dir, file_info.filename)
                        
                        # Create directory if needed
                        os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                        
                        # Extract file
                        with zip_ref.open(file_info) as src, open(extracted_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                            
                        extracted_files.append(extracted_path)
                        
                        # Build file list
                        self.files.append({
                            'path': file_info.filename,
                            'size': file_info.file_size,
                            'extract_path': extracted_path
                        })
            
            self.logger.info(f"Extracted {len(extracted_files)} files to {self.extraction_dir}")
            return extracted_files
            
        except zipfile.BadZipFile:
            self.logger.error(f"Invalid ZIP file: {self.package_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error extracting package: {e}")
            return []
    
    def analyze_android_package(self) -> Dict[str, Any]:
        """Analyze Android package (APK)
        
        Returns:
            Dictionary with analysis results
        """
        if not self.files:
            self.extract_package()
            
        # Parse AndroidManifest.xml
        self._parse_android_manifest()
        
        # Find native libraries
        self._find_android_native_libs()
        
        # Parse certificates
        self._parse_android_certificates()
        
        # Extract strings from resources
        self._extract_android_strings()
        
        # Identify potential security issues
        self._identify_android_security_issues()
        
        # Collect results
        results = {
            "package_info": self.package_info,
            "manifest": self.manifest,
            "permissions": self.permissions,
            "native_libraries": self.native_libraries,
            "certificates": self.certificates,
            "potential_issues": self.potential_issues
        }
        
        # Write results to JSON file
        output_path = os.path.join(self.extraction_dir, "apk_analysis.json")
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        return results
    
    def _parse_android_manifest(self):
        """Parse Android manifest file"""
        manifest_path = os.path.join(self.extraction_dir, "AndroidManifest.xml")
        
        if not os.path.exists(manifest_path):
            self.logger.error("AndroidManifest.xml not found")
            return
            
        try:
            # For binary XML, we need to use AAPT or similar tool to decode it
            # This is a simplified approach assuming the manifest is already decoded
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract package info
            if 'package' in root.attrib:
                self.package_info['package_name'] = root.attrib['package']
                
            # Extract version info
            if 'versionCode' in root.attrib:
                self.package_info['version_code'] = root.attrib['versionCode']
            if 'versionName' in root.attrib:
                self.package_info['version_name'] = root.attrib['versionName']
                
            # Extract permissions
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            for perm in root.findall(".//uses-permission", ns):
                if '{http://schemas.android.com/apk/res/android}name' in perm.attrib:
                    self.permissions.append(perm.attrib['{http://schemas.android.com/apk/res/android}name'])
                    
            # Extract activities, services, receivers, providers
            components = {
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }
            
            for activity in root.findall(".//activity", ns):
                if '{http://schemas.android.com/apk/res/android}name' in activity.attrib:
                    components['activities'].append(activity.attrib['{http://schemas.android.com/apk/res/android}name'])
                    
            for service in root.findall(".//service", ns):
                if '{http://schemas.android.com/apk/res/android}name' in service.attrib:
                    components['services'].append(service.attrib['{http://schemas.android.com/apk/res/android}name'])
                    
            for receiver in root.findall(".//receiver", ns):
                if '{http://schemas.android.com/apk/res/android}name' in receiver.attrib:
                    components['receivers'].append(receiver.attrib['{http://schemas.android.com/apk/res/android}name'])
                    
            for provider in root.findall(".//provider", ns):
                if '{http://schemas.android.com/apk/res/android}name' in provider.attrib:
                    components['providers'].append(provider.attrib['{http://schemas.android.com/apk/res/android}name'])
            
            self.manifest = {
                'package_info': self.package_info,
                'permissions': self.permissions,
                'components': components
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing AndroidManifest.xml: {e}")
    
    def _find_android_native_libs(self):
        """Find native libraries in APK"""
        native_lib_paths = [f for f in self.files if f['path'].startswith('lib/') and f['path'].endswith('.so')]
        
        # Group by architecture
        for lib in native_lib_paths:
            parts = lib['path'].split('/')
            if len(parts) >= 3:
                arch = parts[1]  # lib/x86/libsomething.so -> x86
                name = parts[-1]
                
                self.native_libraries.append({
                    'name': name,
                    'architecture': arch,
                    'path': lib['path'],
                    'size': lib['size']
                })
    
    def _parse_android_certificates(self):
        """Parse Android certificates"""
        cert_paths = [f for f in self.files if f['path'].startswith('META-INF/') and 
                     (f['path'].endswith('.RSA') or f['path'].endswith('.DSA'))]
        
        # For now, just record certificate files
        for cert in cert_paths:
            self.certificates.append({
                'path': cert['path'],
                'size': cert['size']
            })

    def _extract_android_strings(self):
        """Extract strings from Android resources"""
        string_files = [f for f in self.files if f['path'].startswith('res/values') and 'strings.xml' in f['path']]
        
        for file_info in string_files:
            try:
                tree = ET.parse(file_info['extract_path'])
                root = tree.getroot()
                
                # Extract string resources
                strings = {}
                for string in root.findall('./string'):
                    if 'name' in string.attrib:
                        strings[string.attrib['name']] = string.text if string.text else ""
                
                # Add strings to collection
                self.strings[file_info['path']] = strings
                
            except Exception as e:
                self.logger.error(f"Error parsing strings file {file_info['path']}: {e}")
    
    def _identify_android_security_issues(self):
        """Identify potential security issues in Android package"""
        # Check for dangerous permissions
        dangerous_permissions = [
            'android.permission.READ_PHONE_STATE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.READ_SMS',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.CALL_PHONE'
        ]
        
        for perm in self.permissions:
            if perm in dangerous_permissions:
                self.potential_issues.append({
                    'type': 'permission',
                    'severity': 'medium',
                    'description': f"Uses potentially dangerous permission: {perm}"
                })
                
        # Check for backup flag
        if 'allowBackup' in self.manifest.get('package_info', {}) and self.manifest['package_info']['allowBackup'] == 'true':
            self.potential_issues.append({
                'type': 'configuration',
                'severity': 'low',
                'description': "Application allows backup, potentially exposing sensitive data"
            })

    def analyze_ios_package(self) -> Dict[str, Any]:
        """Analyze iOS package (IPA)
        
        Returns:
            Dictionary with analysis results
        """
        if not self.files:
            self.extract_package()
            
        # Parse Info.plist
        self._parse_ios_info_plist()
        
        # Find native binaries and frameworks
        self._find_ios_binaries()
        
        # Extract entitlements
        self._extract_ios_entitlements()
        
        # Identify potential security issues
        self._identify_ios_security_issues()
        
        # Collect results
        results = {
            "package_info": self.package_info,
            "binaries": self.native_libraries,
            "entitlements": self.permissions,  # Repurpose permissions list for entitlements
            "potential_issues": self.potential_issues
        }
        
        # Write results to JSON file
        output_path = os.path.join(self.extraction_dir, "ipa_analysis.json")
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        return results
    
    def _parse_ios_info_plist(self):
        """Parse iOS Info.plist file"""
        # Find Info.plist in the payload directory
        plist_paths = [f for f in self.files if '/Info.plist' in f['path']]
        
        if not plist_paths:
            self.logger.error("Info.plist not found")
            return
            
        try:
            # Use the first Info.plist found
            with open(plist_paths[0]['extract_path'], 'rb') as f:
                plist_data = plistlib.load(f)
                
            # Extract package info
            self.package_info = {
                'bundle_id': plist_data.get('CFBundleIdentifier', ''),
                'name': plist_data.get('CFBundleName', ''),
                'version': plist_data.get('CFBundleShortVersionString', ''),
                'build': plist_data.get('CFBundleVersion', '')
            }
            
            # Store full plist data
            self.manifest = plist_data
            
        except Exception as e:
            self.logger.error(f"Error parsing Info.plist: {e}")
    
    def _find_ios_binaries(self):
        """Find native binaries and frameworks in IPA"""
        # Look for Mach-O binaries in Payload directory
        # This is a simplified approach - in reality we would use tools like lipo to analyze architectures
        executable_name = self.manifest.get('CFBundleExecutable', '')
        
        if executable_name:
            exec_paths = [f for f in self.files if executable_name in f['path'] and not f['path'].endswith('/')]
            
            for path in exec_paths:
                # Check if it's a Mach-O binary
                try:
                    with open(path['extract_path'], 'rb') as f:
                        magic = f.read(4)
                        
                    if magic in [b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                             b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                        self.native_libraries.append({
                            'name': os.path.basename(path['path']),
                            'path': path['path'],
                            'size': path['size'],
                            'type': 'executable'
                        })
                except:
                    pass
                    
        # Look for frameworks
        frameworks = [f for f in self.files if '.framework/' in f['path']]
        
        # Group frameworks by name
        framework_names = set()
        for f in frameworks:
            path_parts = f['path'].split('.framework/')
            if len(path_parts) > 0:
                framework_name = os.path.basename(path_parts[0])
                framework_names.add(framework_name)
                
        # Add frameworks to native libraries list
        for name in framework_names:
            self.native_libraries.append({
                'name': name,
                'path': f"{name}.framework",
                'type': 'framework'
            })
    
    def _extract_ios_entitlements(self):
        """Extract entitlements from iOS package"""
        # Entitlements are typically embedded in the binary
        # For a real implementation, we would use tools like codesign to extract them
        # For now, we'll look for common entitlement identifiers in the Info.plist
        
        entitlement_keys = [
            'com.apple.developer.networking.vpn.api',
            'com.apple.developer.in-app-payments',
            'com.apple.developer.associated-domains',
            'com.apple.developer.healthkit',
            'com.apple.security.application-groups'
        ]
        
        for key in entitlement_keys:
            if key in self.manifest:
                self.permissions.append({
                    'name': key,
                    'value': str(self.manifest[key])
                })
    
    def _identify_ios_security_issues(self):
        """Identify potential security issues in iOS package"""
        # Check for ATS disabled
        if 'NSAppTransportSecurity' in self.manifest:
            ats = self.manifest['NSAppTransportSecurity']
            if isinstance(ats, dict) and ats.get('NSAllowsArbitraryLoads') is True:
                self.potential_issues.append({
                    'type': 'security',
                    'severity': 'high',
                    'description': "App Transport Security is disabled, allowing insecure connections"
                })
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate app analysis report
        
        Args:
            output_file: Path to save the report to
            
        Returns:
            Path to the generated report
        """
        # Run analysis if not already done
        if self.package_type == '.apk':
            if not self.package_info:
                self.analyze_android_package()
            report_type = "Android"
        elif self.package_type == '.ipa':
            if not self.package_info:
                self.analyze_ios_package()
            report_type = "iOS"
        else:
            raise ValueError(f"Unsupported package type: {self.package_type}")
            
        # Create report directory
        report_dir = os.path.join(self.extraction_dir, "report")
        os.makedirs(report_dir, exist_ok=True)
        
        # Set default output file if not provided
        if not output_file:
            output_file = os.path.join(report_dir, f"{report_type.lower()}_app_analysis_report.md")
        
        # Generate report content
        report = f"""# {report_type} App Analysis Report

## Package Information

- **Name:** {self.package_info.get('name', self.package_info.get('package_name', 'Unknown'))}
- **ID:** {self.package_info.get('package_name', self.package_info.get('bundle_id', 'Unknown'))}
- **Version:** {self.package_info.get('version_name', self.package_info.get('version', 'Unknown'))}

## Component Overview

"""
        
        if report_type == "Android":
            # Add Android-specific sections
            report += f"- **Activities:** {len(self.manifest.get('components', {}).get('activities', []))}\n"
            report += f"- **Services:** {len(self.manifest.get('components', {}).get('services', []))}\n"
            report += f"- **Receivers:** {len(self.manifest.get('components', {}).get('receivers', []))}\n"
            report += f"- **Providers:** {len(self.manifest.get('components', {}).get('providers', []))}\n\n"
            
            report += "## Permissions\n\n"
            for perm in self.permissions:
                report += f"- {perm}\n"
                
        elif report_type == "iOS":
            # Add iOS-specific sections
            report += f"- **Minimum OS Version:** {self.manifest.get('MinimumOSVersion', 'Unknown')}\n\n"
            
            report += "## Entitlements\n\n"
            for ent in self.permissions:
                report += f"- {ent['name']}: {ent['value']}\n"
        
        # Add native libraries section
        report += "\n## Native Libraries\n\n"
        for lib in self.native_libraries:
            if report_type == "Android":
                report += f"- {lib['name']} ({lib['architecture']})\n"
            else:
                report += f"- {lib['name']} ({lib.get('type', 'binary')})\n"
        
        # Add security issues section
        report += "\n## Security Issues\n\n"
        if self.potential_issues:
            for issue in self.potential_issues:
                severity = issue['severity'].upper()
                report += f"- [{severity}] {issue['description']}\n"
        else:
            report += "No obvious security issues detected.\n"
        
        # Write report to file
        with open(output_file, 'w') as f:
            f.write(report)
            
        return output_file
