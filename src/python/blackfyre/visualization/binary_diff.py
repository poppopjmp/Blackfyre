"""Binary difference visualization"""

import difflib
import os
import tempfile
import webbrowser
from typing import Dict, List, Optional, Union, Tuple
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.analysis.differential import BinaryDiff

class BinaryComparisonViewer:
    """Generate visual comparisons between binaries"""
    
    @staticmethod
    def _create_html_template():
        """Create the HTML template for the binary comparison view"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Blackfyre Binary Comparison</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                    color: #343a40;
                }
                header {
                    background-color: #343a40;
                    color: white;
                    padding: 15px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .summary-section {
                    background-color: white;
                    border-radius: 4px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .comparison-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }
                .comparison-card {
                    background-color: white;
                    border-radius: 4px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .function-changes {
                    margin-top: 20px;
                }
                .function-list {
                    max-height: 300px;
                    overflow-y: auto;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 10px;
                }
                .function-item {
                    padding: 5px;
                    border-bottom: 1px solid #f1f1f1;
                    cursor: pointer;
                }
                .function-item:hover {
                    background-color: #f1f1f1;
                }
                .diff-viewer {
                    font-family: monospace;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 10px;
                    margin-top: 20px;
                    background-color: #f8f9fa;
                    white-space: pre;
                    overflow-x: auto;
                }
                .diff-line {
                    margin: 0;
                    padding: 1px 5px;
                }
                .diff-added {
                    background-color: #e6ffec;
                    color: #22863a;
                }
                .diff-removed {
                    background-color: #ffebe9;
                    color: #da3633;
                }
                .diff-unchanged {
                    color: #24292f;
                }
                .diff-info {
                    color: #0550ae;
                    background-color: #ddf4ff;
                }
                .security-findings {
                    margin-top: 20px;
                    background-color: white;
                    border-radius: 4px;
                    padding: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .security-item {
                    border-left: 4px solid;
                    padding: 10px;
                    margin-bottom: 10px;
                }
                .security-item.high {
                    border-color: #da3633;
                }
                .security-item.medium {
                    border-color: #f2a846;
                }
                .security-item.low {
                    border-color: #2da44e;
                }
                .nav-tabs {
                    display: flex;
                    border-bottom: 1px solid #dee2e6;
                    margin-bottom: 20px;
                }
                .nav-tab {
                    padding: 10px 15px;
                    cursor: pointer;
                    background-color: transparent;
                    border: none;
                    border-bottom: 2px solid transparent;
                    transition: border-color 0.2s;
                }
                .nav-tab.active {
                    border-bottom: 2px solid #0366d6;
                    color: #0366d6;
                }
                .tab-content {
                    display: none;
                }
                .tab-content.active {
                    display: block;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>Binary Comparison</h1>
            </header>
            
            <div class="container">
                <div class="summary-section">
                    <h2>Summary</h2>
                    <div id="summary-content"></div>
                </div>
                
                <div class="nav-tabs">
                    <button class="nav-tab active" data-tab="functions-tab">Functions</button>
                    <button class="nav-tab" data-tab="strings-tab">Strings</button>
                    <button class="nav-tab" data-tab="imports-tab">Imports</button>
                    <button class="nav-tab" data-tab="security-tab">Security</button>
                </div>
                
                <div class="tab-content active" id="functions-tab">
                    <div class="comparison-grid">
                        <div class="comparison-card">
                            <h3>Added Functions</h3>
                            <p id="added-functions-count"></p>
                            <div class="function-list" id="added-functions-list"></div>
                        </div>
                        <div class="comparison-card">
                            <h3>Removed Functions</h3>
                            <p id="removed-functions-count"></p>
                            <div class="function-list" id="removed-functions-list"></div>
                        </div>
                    </div>
                    <div class="comparison-card function-changes">
                        <h3>Modified Functions</h3>
                        <p id="modified-functions-count"></p>
                        <div class="function-list" id="modified-functions-list"></div>
                        
                        <div class="diff-viewer" id="function-diff-viewer">
                            <p>Select a function to view differences</p>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="strings-tab">
                    <div class="comparison-grid">
                        <div class="comparison-card">
                            <h3>Added Strings</h3>
                            <p id="added-strings-count"></p>
                            <div class="function-list" id="added-strings-list"></div>
                        </div>
                        <div class="comparison-card">
                            <h3>Removed Strings</h3>
                            <p id="removed-strings-count"></p>
                            <div class="function-list" id="removed-strings-list"></div>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="imports-tab">
                    <div class="comparison-grid">
                        <div class="comparison-card">
                            <h3>Added Imports</h3>
                            <p id="added-imports-count"></p>
                            <div class="function-list" id="added-imports-list"></div>
                        </div>
                        <div class="comparison-card">
                            <h3>Removed Imports</h3>
                            <p id="removed-imports-count"></p>
                            <div class="function-list" id="removed-imports-list"></div>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="security-tab">
                    <div class="security-findings">
                        <h3>Security Findings</h3>
                        <p id="security-findings-count"></p>
                        <div id="security-findings-list"></div>
                    </div>
                </div>
            </div>
            
            <script>
                // Comparison data
                const comparisonData = COMPARISON_DATA_PLACEHOLDER;
                
                // Fill summary content
                document.getElementById('summary-content').innerHTML = `
                    <p><strong>Original:</strong> ${comparisonData.metadata.name.original} (${comparisonData.metadata.sha256_hash.original})</p>
                    <p><strong>Updated:</strong> ${comparisonData.metadata.name.updated} (${comparisonData.metadata.sha256_hash.updated})</p>
                    <p><strong>File size change:</strong> ${comparisonData.metadata.file_size.diff} bytes</p>
                    <p><strong>Function changes:</strong> ${comparisonData.functions.added_functions.count} added, ${comparisonData.functions.removed_functions.count} removed, ${comparisonData.functions.modified_functions.count} modified</p>
                `;
                
                // Fill functions tab
                document.getElementById('added-functions-count').textContent = 
                    `${comparisonData.functions.added_functions.count} functions added`;
                document.getElementById('removed-functions-count').textContent = 
                    `${comparisonData.functions.removed_functions.count} functions removed`;
                document.getElementById('modified-functions-count').textContent = 
                    `${comparisonData.functions.modified_functions.count} functions modified`;
                
                // Populate function lists
                const addedFunctionsList = document.getElementById('added-functions-list');
                comparisonData.functions.added_functions.addresses.forEach((addr, index) => {
                    const name = comparisonData.functions.added_functions.names[index];
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${name} (0x${addr.toString(16)})`;
                    addedFunctionsList.appendChild(item);
                });
                
                const removedFunctionsList = document.getElementById('removed-functions-list');
                comparisonData.functions.removed_functions.addresses.forEach((addr, index) => {
                    const name = comparisonData.functions.removed_functions.names[index];
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${name} (0x${addr.toString(16)})`;
                    removedFunctionsList.appendChild(item);
                });
                
                const modifiedFunctionsList = document.getElementById('modified-functions-list');
                comparisonData.functions.modified_functions.addresses.forEach((addr, index) => {
                    const name = comparisonData.functions.modified_functions.names[index];
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${name} (0x${addr.toString(16)})`;
                    item.onclick = () => showFunctionDiff(addr);
                    modifiedFunctionsList.appendChild(item);
                });
                
                // Fill strings tab
                document.getElementById('added-strings-count').textContent = 
                    `${comparisonData.strings.added_strings.count} strings added`;
                document.getElementById('removed-strings-count').textContent = 
                    `${comparisonData.strings.removed_strings.count} strings removed`;
                
                // Populate string lists
                const addedStringsList = document.getElementById('added-strings-list');
                comparisonData.strings.added_strings.strings.forEach(([addr, str]) => {
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${addr}: "${str.substring(0, 50)}${str.length > 50 ? '...' : ''}"`;
                    addedStringsList.appendChild(item);
                });
                
                const removedStringsList = document.getElementById('removed-strings-list');
                comparisonData.strings.removed_strings.strings.forEach(([addr, str]) => {
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${addr}: "${str.substring(0, 50)}${str.length > 50 ? '...' : ''}"`;
                    removedStringsList.appendChild(item);
                });
                
                // Fill imports tab
                document.getElementById('added-imports-count').textContent = 
                    `${comparisonData.imports.added_imports.count} imports added`;
                document.getElementById('removed-imports-count').textContent = 
                    `${comparisonData.imports.removed_imports.count} imports removed`;
                
                // Populate import lists
                const addedImportsList = document.getElementById('added-imports-list');
                comparisonData.imports.added_imports.imports.forEach(([name, lib]) => {
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${name} (${lib})`;
                    addedImportsList.appendChild(item);
                });
                
                const removedImportsList = document.getElementById('removed-imports-list');
                comparisonData.imports.removed_imports.imports.forEach(([name, lib]) => {
                    const item = document.createElement('div');
                    item.className = 'function-item';
                    item.textContent = `${name} (${lib})`;
                    removedImportsList.appendChild(item);
                });
                
                // Fill security tab
                document.getElementById('security-findings-count').textContent = 
                    `${comparisonData.security.total_findings} security findings`;
                
                // Populate security findings
                const securityFindingsList = document.getElementById('security-findings-list');
                comparisonData.security.findings.forEach((finding, index) => {
                    const item = document.createElement('div');
                    item.className = `security-item ${finding.severity}`;
                    
                    let content = `<h4>${index + 1}. ${finding.description}</h4>`;
                    content += `<p><strong>Type:</strong> ${finding.type}</p>`;
                    content += `<p><strong>Severity:</strong> ${finding.severity}</p>`;
                    
                    if (finding.type === 'added_import' || finding.type === 'removed_import') {
                        content += `<p><strong>Function:</strong> ${finding.name}</p>`;
                        content += `<p><strong>Library:</strong> ${finding.library}</p>`;
                    } else if (finding.type === 'added_string' || finding.type === 'removed_string') {
                        content += `<p><strong>Address:</strong> ${finding.address}</p>`;
                        content += `<p><strong>String:</strong> "${finding.string}"</p>`;
                    }
                    
                    item.innerHTML = content;
                    securityFindingsList.appendChild(item);
                });
                
                // Function to show function diff
                function showFunctionDiff(functionAddr) {
                    const diffViewer = document.getElementById('function-diff-viewer');
                    
                    // In a real implementation, we would make an AJAX request to get the diff
                    // For this demo, we'll simulate it with placeholder content
                    diffViewer.innerHTML = `<p class="diff-info">@@ -1,5 +1,6 @@</p>
<p class="diff-unchanged">int main(int argc, char *argv[]) {</p>
<p class="diff-removed">    printf("Hello, world!");</p>
<p class="diff-added">    printf("Hello, updated world!");</p>
<p class="diff-added">    printf("This is a new line");</p>
<p class="diff-unchanged">    return 0;</p>
<p class="diff-unchanged">}</p>`;
                }
                
                // Tab switching
                document.querySelectorAll('.nav-tab').forEach(tab => {
                    tab.addEventListener('click', function() {
                        // Remove active class from all tabs and content
                        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                        
                        // Add active class to clicked tab
                        this.classList.add('active');
                        
                        // Show corresponding content
                        const tabId = this.getAttribute('data-tab');
                        document.getElementById(tabId).classList.add('active');
                    });
                });
            </script>
        </body>
        </html>
        """
    
    @classmethod
    def visualize_diff(cls, original_bcc: BinaryContext, updated_bcc: BinaryContext) -> str:
        """Generate an interactive visualization of binary differences
        
        Args:
            original_bcc: The original/older BinaryContext
            updated_bcc: The updated/newer BinaryContext
            
        Returns:
            Path to the generated HTML file
        """
        # Create binary diff analyzer
        differ = BinaryDiff(original_bcc, updated_bcc)
        
        # Collect data for visualization
        metadata = differ.compare_metadata()
        functions = differ.compare_functions()
        strings = differ.compare_strings()
        imports = differ.compare_imports()
        security = differ.analyze_security_implications()
        
        # Combine data for the template
        comparison_data = {
            "metadata": metadata,
            "functions": functions,
            "strings": strings,
            "imports": imports,
            "security": security
        }
        
        # Generate HTML
        html_template = cls._create_html_template()
        import json
        html = html_template.replace("COMPARISON_DATA_PLACEHOLDER", json.dumps(comparison_data))
        
        # Write to temp file and open in browser
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
            f.write(html)
            filename = f.name
        
        webbrowser.open('file://' + os.path.abspath(filename))
        
        return filename
