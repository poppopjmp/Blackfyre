"""PDF file analyzer for Blackfyre"""

import os
import re
import json
import logging
import binascii
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Iterator
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class PDFAnalyzer:
    """Analyzer for PDF files"""
    
    def __init__(self, 
                 pdf_path: str,
                 extraction_dir: Optional[str] = None):
        """Initialize the PDF analyzer
        
        Args:
            pdf_path: Path to PDF file
            extraction_dir: Directory to extract embedded objects
        """
        self.pdf_path = pdf_path
        
        # Validate PDF path
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
            
        # Set up extraction directory
        if extraction_dir:
            self.extraction_dir = Path(extraction_dir)
        else:
            # Default extraction directory next to PDF file
            parent = Path(pdf_path).parent
            base_name = Path(pdf_path).stem
            self.extraction_dir = parent / f"{base_name}_pdf_analysis"
            
        self.logger = logging.getLogger(__name__)
        
        # Data
        self.pdf_data = None
        self.xref_tables = []
        self.objects = {}
        self.suspicious_objects = []
        self.javascript_code = []
        self.embedded_files = []
    
    def load_pdf(self) -> bool:
        """Load PDF data from file
        
        Returns:
            True if successfully loaded
        """
        try:
            with open(self.pdf_path, 'rb') as f:
                self.pdf_data = f.read()
            self.logger.info(f"Loaded {len(self.pdf_data)} bytes from {self.pdf_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading PDF file: {e}")
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze PDF file
        
        Returns:
            Dictionary with analysis results
        """
        if not self.pdf_data:
            if not self.load_pdf():
                return {}
        
        # Create extraction directory
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Initial validation
        if not self._validate_pdf_header():
            self.logger.error("Invalid PDF header")
            return {"error": "Invalid PDF header"}
            
        # Locate and parse xref tables
        self._locate_xref_tables()
        
        # Parse PDF objects
        self._parse_objects()
        
        # Scan for suspicious elements
        self._scan_for_suspicious_elements()
        
        # Extract embedded files
        self._extract_embedded_files()
        
        # Analyze document structure
        doc_info = self._analyze_document_structure()
        
        # Collect results
        results = {
            "document_info": doc_info,
            "object_count": len(self.objects),
            "xref_tables": len(self.xref_tables),
            "suspicious_elements": self.suspicious_objects,
            "javascript": self.javascript_code,
            "embedded_files": self.embedded_files
        }
        
        # Write results to JSON file
        output_path = os.path.join(self.extraction_dir, "pdf_analysis.json")
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        return results
    
    def _validate_pdf_header(self) -> bool:
        """Validate PDF header
        
        Returns:
            True if PDF header is valid
        """
        # Check if file starts with %PDF-
        return self.pdf_data[:5].startswith(b'%PDF-')
    
    def _locate_xref_tables(self):
        """Locate and parse xref tables"""
        # Find all startxref positions
        startxref_positions = [m.start() for m in re.finditer(b'startxref', self.pdf_data)]
        
        for pos in startxref_positions:
            # Extract offset of xref table
            xref_offset = self._extract_number_after(pos + 9)
            
            if xref_offset is not None:
                self.xref_tables.append(xref_offset)
    
    def _extract_number_after(self, pos: int) -> Optional[int]:
        """Extract number after position
        
        Args:
            pos: Position in file
            
        Returns:
            Extracted number or None if not found
        """
        # Skip whitespace
        while pos < len(self.pdf_data) and self.pdf_data[pos:pos+1].isspace():
            pos += 1
            
        # Extract number
        num_str = b''
        while pos < len(self.pdf_data) and self.pdf_data[pos:pos+1].isdigit():
            num_str += self.pdf_data[pos:pos+1]
            pos += 1
            
        if num_str:
            return int(num_str)
        return None
    
    def _parse_objects(self):
        """Parse PDF objects"""
        # Find all object definitions (n n obj)
        obj_pattern = re.compile(rb'(\d+)\s+(\d+)\s+obj')
        obj_matches = obj_pattern.finditer(self.pdf_data)
        
        for match in obj_matches:
            obj_id = int(match.group(1))
            gen_id = int(match.group(2))
            start_pos = match.start()
            
            # Find end of object
            end_marker = f"{obj_id} {gen_id} endobj".encode()
            end_pos = self.pdf_data.find(end_marker, start_pos)
            
            if end_pos != -1:
                # Extract object data
                obj_data = self.pdf_data[start_pos:end_pos + len(end_marker)]
                
                self.objects[(obj_id, gen_id)] = {
                    'offset': start_pos,
                    'size': len(obj_data),
                    'data': obj_data
                }
    
    def _scan_for_suspicious_elements(self):
        """Scan for suspicious elements in PDF"""
        # Look for JavaScript
        js_pattern = re.compile(rb'/JavaScript\s*<<', re.IGNORECASE)
        js_stream_pattern = re.compile(rb'/JS\s*\(', re.IGNORECASE)
        aa_pattern = re.compile(rb'/AA\s*<<', re.IGNORECASE)  # Additional Actions
        openaction_pattern = re.compile(rb'/OpenAction\s*<<', re.IGNORECASE)
        launch_pattern = re.compile(rb'/Launch\s*<<', re.IGNORECASE)
        
        for (obj_id, gen_id), obj in self.objects.items():
            obj_data = obj['data']
            
            # Check for JavaScript
            if js_pattern.search(obj_data) or js_stream_pattern.search(obj_data):
                self.suspicious_objects.append({
                    'object_id': f"{obj_id} {gen_id}",
                    'type': 'javascript',
                    'offset': obj['offset']
                })
                
                # Extract JavaScript code
                self._extract_javascript(obj_data, obj_id, gen_id)
                
            # Check for automatic actions
            if aa_pattern.search(obj_data) or openaction_pattern.search(obj_data):
                self.suspicious_objects.append({
                    'object_id': f"{obj_id} {gen_id}",
                    'type': 'automatic_action',
                    'offset': obj['offset']
                })
                
            # Check for Launch actions
            if launch_pattern.search(obj_data):
                self.suspicious_objects.append({
                    'object_id': f"{obj_id} {gen_id}",
                    'type': 'launch_action',
                    'offset': obj['offset'],
                    'severity': 'high'
                })
                
            # Check for potential shellcode (hex-encoded or hex sequences)
            if re.search(rb'\\x[0-9a-fA-F]{2}', obj_data) or re.search(rb'[0-9a-fA-F]{40,}', obj_data):
                self.suspicious_objects.append({
                    'object_id': f"{obj_id} {gen_id}",
                    'type': 'potential_shellcode',
                    'offset': obj['offset'],
                    'severity': 'high'
                })
    
    def _extract_javascript(self, obj_data: bytes, obj_id: int, gen_id: int):
        """Extract JavaScript code from object
        
        Args:
            obj_data: Object data
            obj_id: Object ID
            gen_id: Generation ID
        """
        # Find JavaScript code
        js_start = obj_data.find(b'/JS')
        if js_start == -1:
            return
            
        # Find opening delimiter after /JS
        paren_start = obj_data.find(b'(', js_start)
        lt_start = obj_data.find(b'<', js_start)
        
        if paren_start == -1 and lt_start == -1:
            return
            
        # Determine which delimiter was found first
        if paren_start != -1 and (lt_start == -1 or paren_start < lt_start):
            # JavaScript is in a literal string
            js_start = paren_start + 1
            js_end = obj_data.find(b')', js_start)
            if js_end == -1:
                return
                
            js_code = obj_data[js_start:js_end]
            
            # Unescape if needed
            js_code = js_code.replace(b'\\(', b'(').replace(b'\\)', b')')
            
        else:
            # JavaScript is in a hex string
            if obj_data[lt_start:lt_start+2] == b'<<':
                # It's a dictionary, need to find the stream
                stream_start = obj_data.find(b'stream', lt_start)
                if stream_start == -1:
                    return
                    
                # Skip to end of 'stream' keyword and any trailing newline
                stream_start += 6
                if obj_data[stream_start:stream_start+1] == b'\r':
                    stream_start += 1
                if obj_data[stream_start:stream_start+1] == b'\n':
                    stream_start += 1
                    
                stream_end = obj_data.find(b'endstream', stream_start)
                if stream_end == -1:
                    return
                    
                js_code = obj_data[stream_start:stream_end]
                
            else:
                # Hex string
                js_start = lt_start + 1
                js_end = obj_data.find(b'>', js_start)
                if js_end == -1:
                    return
                    
                # Convert hex to bytes
                hex_str = obj_data[js_start:js_end]
                # Remove whitespace
                hex_str = re.sub(rb'\s', b'', hex_str)
                try:
                    js_code = binascii.unhexlify(hex_str)
                except:
                    # Not valid hex
                    return
        
        # Save JavaScript code
        output_path = os.path.join(self.extraction_dir, f"javascript_{obj_id}_{gen_id}.js")
        with open(output_path, 'wb') as f:
            f.write(js_code)
            
        self.javascript_code.append({
            'object_id': f"{obj_id} {gen_id}",
            'path': output_path,
            'size': len(js_code)
        })
    
    def _extract_embedded_files(self):
        """Extract embedded files"""
        # Look for file specifications
        filespec_pattern = re.compile(rb'/Type\s*/Filespec', re.IGNORECASE)
        embeddedfile_pattern = re.compile(rb'/Type\s*/EmbeddedFile', re.IGNORECASE)
        
        for (obj_id, gen_id), obj in self.objects.items():
            obj_data = obj['data']
            
            if filespec_pattern.search(obj_data) or embeddedfile_pattern.search(obj_data):
                # This object might contain an embedded file
                filename = self._extract_filename_from_filespec(obj_data)
                
                # Find associated stream object (if any)
                stream_obj = self._find_stream_object_for_filespec(obj_id, gen_id)
                
                if stream_obj:
                    # Extract embedded file
                    stream_data = self._extract_stream_content(stream_obj['data'])
                    
                    if stream_data and filename:
                        # Write to file
                        safe_filename = re.sub(r'[^\w\-\.]', '_', filename)
                        output_path = os.path.join(self.extraction_dir, f"embedded_{obj_id}_{safe_filename}")
                        
                        with open(output_path, 'wb') as f:
                            f.write(stream_data)
                            
                        # Add to embedded files list
                        self.embedded_files.append({
                            'object_id': f"{obj_id} {gen_id}",
                            'filename': filename,
                            'size': len(stream_data),
                            'path': output_path
                        })
    
    def _extract_filename_from_filespec(self, obj_data: bytes) -> str:
        """Extract filename from file specification object
        
        Args:
            obj_data: Object data
            
        Returns:
            Extracted filename or empty string if not found
        """
        # Look for /F (filename) entry
        f_match = re.search(rb'/F\s*\(([^)]+)\)', obj_data)
        if f_match:
            return f_match.group(1).decode('utf-8', errors='replace')
            
        # Look for /UF (unicode filename) entry
        uf_match = re.search(rb'/UF\s*\(([^)]+)\)', obj_data)
        if uf_match:
            return uf_match.group(1).decode('utf-8', errors='replace')
            
        return ""
    
    def _find_stream_object_for_filespec(self, filespec_id: int, filespec_gen: int) -> Optional[Dict[str, Any]]:
        """Find stream object associated with a file specification
        
        Args:
            filespec_id: File specification object ID
            filespec_gen: File specification generation ID
            
        Returns:
            Stream object or None if not found
        """
        # This is a simplified approach - in reality, we would follow object references
        # For now, just look for stream objects near the file specification
        for (obj_id, gen_id), obj in self.objects.items():
            if obj_id == filespec_id + 1 and b'stream' in obj['data'] and b'endstream' in obj['data']:
                return obj
                
        return None
    
    def _extract_stream_content(self, obj_data: bytes) -> Optional[bytes]:
        """Extract content from stream object
        
        Args:
            obj_data: Object data
            
        Returns:
            Stream content or None if extraction failed
        """
        # Find stream and endstream markers
        stream_start = obj_data.find(b'stream')
        if stream_start == -1:
            return None
            
        # Skip to end of 'stream' keyword and any trailing newline
        stream_start += 6
        if obj_data[stream_start:stream_start+1] == b'\r':
            stream_start += 1
        if obj_data[stream_start:stream_start+1] == b'\n':
            stream_start += 1
            
        stream_end = obj_data.find(b'endstream', stream_start)
        if stream_end == -1:
            return None
            
        # Extract stream content
        return obj_data[stream_start:stream_end]
    
    def _analyze_document_structure(self) -> Dict[str, Any]:
        """Analyze PDF document structure
        
        Returns:
            Dictionary with document information
        """
        doc_info = {
            "version": "",
            "title": "",
            "author": "",
            "creator": "",
            "producer": "",
            "creation_date": "",
            "mod_date": "",
            "page_count": 0,
            "encrypted": False
        }
        
        # Extract PDF version from header
        header_match = re.match(rb'%PDF-(\d+\.\d+)', self.pdf_data)
        if header_match:
            doc_info["version"] = header_match.group(1).decode()
        
        # Look for document information dictionary
        for (obj_id, gen_id), obj in self.objects.items():
            obj_data = obj['data']
            
            # Check for Info dictionary
            if b'/Info' in obj_data:
                # Extract standard info fields
                for field, pattern in [
                    ("title", rb'/Title\s*\(([^)]+)\)'),
                    ("author", rb'/Author\s*\(([^)]+)\)'),
                    ("creator", rb'/Creator\s*\(([^)]+)\)'),
                    ("producer", rb'/Producer\s*\(([^)]+)\)'),
                    ("creation_date", rb'/CreationDate\s*\(([^)]+)\)'),
                    ("mod_date", rb'/ModDate\s*\(([^)]+)\)')
                ]:
                    match = re.search(pattern, obj_data)
                    if match:
                        doc_info[field] = match.group(1).decode('utf-8', errors='replace')
            
            # Check for Pages object to get page count
            if b'/Type/Pages' in obj_data:
                count_match = re.search(rb'/Count\s+(\d+)', obj_data)
                if count_match:
                    doc_info["page_count"] = int(count_match.group(1))
                    
            # Check for encryption
            if b'/Encrypt' in obj_data:
                doc_info["encrypted"] = True
        
        return doc_info
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate PDF analysis report
        
        Args:
            output_file: Path to save the report to
            
        Returns:
            Path to the generated report
        """
        # Run analysis if not already done
        if not hasattr(self, 'suspicious_objects') or not self.suspicious_objects:
            self.analyze()
            
        # Create report directory
        report_dir = os.path.join(self.extraction_dir, "report")
        os.makedirs(report_dir, exist_ok=True)
        
        # Set default output file if not provided
        if not output_file:
            output_file = os.path.join(report_dir, "pdf_analysis_report.md")
        
        # Get document info
        doc_info = self._analyze_document_structure()
        
        # Generate report content
        report = f"""# PDF Analysis Report

## Document Information

- **Filename:** {os.path.basename(self.pdf_path)}
- **Size:** {os.path.getsize(self.pdf_path)} bytes
- **Version:** {doc_info['version']}
- **Title:** {doc_info['title']}
- **Author:** {doc_info['author']}
- **Creator:** {doc_info['creator']}
- **Producer:** {doc_info['producer']}
- **Creation Date:** {doc_info['creation_date']}
- **Modified Date:** {doc_info['mod_date']}
- **Page Count:** {doc_info['page_count']}
- **Encrypted:** {'Yes' if doc_info['encrypted'] else 'No'}

## Structure Overview

- **Objects:** {len(self.objects)}
- **Cross-reference Tables:** {len(self.xref_tables)}

## Security Analysis

"""
        
        # Add suspicious elements
        if self.suspicious_objects:
            report += "### Suspicious Elements\n\n"
            
            # Group by type
            elements_by_type = {}
            for obj in self.suspicious_objects:
                obj_type = obj['type']
                severity = obj.get('severity', 'medium')
                
                if obj_type not in elements_by_type:
                    elements_by_type[obj_type] = []
                    
                elements_by_type[obj_type].append((obj['object_id'], severity))
            
            # Add each type
            for obj_type, elements in elements_by_type.items():
                report += f"#### {obj_type.replace('_', ' ').title()}\n\n"
                for obj_id, severity in elements:
                    report += f"- Object {obj_id} ({severity.upper()})\n"
                report += "\n"
        else:
            report += "No suspicious elements found.\n\n"
            
        # Add JavaScript section
        if self.javascript_code:
            report += f"### JavaScript ({len(self.javascript_code)} instances)\n\n"
            for js in self.javascript_code:
                report += f"- Object {js['object_id']}: {js['size']} bytes, extracted to {os.path.basename(js['path'])}\n"
            report += "\n"
            
        # Add embedded files section
        if self.embedded_files:
            report += f"### Embedded Files ({len(self.embedded_files)})\n\n"
            for file in self.embedded_files:
                report += f"- {file['filename']} ({file['size']} bytes), from Object {file['object_id']}\n"
                report += f"  - Extracted to: {os.path.basename(file['path'])}\n"
            report += "\n"
        
        # Write report to file
        with open(output_file, 'w') as f:
            f.write(report)
            
        return output_file
