import json
import webbrowser
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union

class InteractiveVisualization:
    """Generate interactive web visualizations for binary analysis"""
    
    @staticmethod
    def _create_html_template():
        """Create the HTML template for visualization
        
        Returns:
            The HTML template as a string
        """
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Blackfyre Interactive Visualization</title>
            <script src="https://d3js.org/d3.v7.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/d3-force-boundary@0.0.1/dist/d3-force-boundary.min.js"></script>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                    color: #343a40;
                }
                #header {
                    background-color: #343a40;
                    color: white;
                    padding: 15px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                #title {
                    margin: 0;
                }
                #controls {
                    display: flex;
                    gap: 10px;
                }
                .btn {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                .btn:hover {
                    background-color: #0069d9;
                }
                #main-container {
                    display: flex;
                    height: calc(100vh - 60px);
                }
                #graph {
                    flex-grow: 1;
                    height: 100%;
                    position: relative;
                    overflow: hidden;
                }
                #sidebar {
                    width: 300px;
                    height: 100%;
                    background: white;
                    overflow-y: auto;
                    border-left: 1px solid #dee2e6;
                    box-shadow: -2px 0 5px rgba(0,0,0,0.05);
                    padding: 15px;
                }
                .sidebar-section {
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid #dee2e6;
                }
                .sidebar-section h3 {
                    margin-top: 0;
                    color: #495057;
                }
                .node {
                    cursor: pointer;
                }
                .link {
                    stroke: #999;
                    stroke-opacity: 0.6;
                    stroke-width: 1px;
                }
                .tooltip {
                    position: absolute;
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    padding: 10px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    pointer-events: none;
                    opacity: 0;
                    transition: opacity 0.2s;
                }
                .search-container {
                    margin-bottom: 15px;
                }
                #search-input {
                    width: 100%;
                    padding: 8px 12px;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    box-sizing: border-box;
                    margin-top: 5px;
                }
                .filter-options {
                    margin-top: 10px;
                }
                .checkbox-item {
                    margin-bottom: 5px;
                }
                #node-info {
                    background-color: #f8f9fa;
                    border-radius: 4px;
                    padding: 10px;
                }
                #node-info p {
                    margin: 5px 0;
                }
                #node-info strong {
                    color: #495057;
                }
                .info-item {
                    margin-bottom: 5px;
                }
            </style>
        </head>
        <body>
            <div id="header">
                <h2 id="title">Blackfyre: BINARY_NAME_PLACEHOLDER</h2>
                <div id="controls">
                    <button id="zoom-in" class="btn">Zoom In</button>
                    <button id="zoom-out" class="btn">Zoom Out</button>
                    <button id="reset-view" class="btn">Reset View</button>
                </div>
            </div>
            <div id="main-container">
                <div id="graph"></div>
                <div id="sidebar">
                    <div class="sidebar-section">
                        <h3>Binary Information</h3>
                        <div id="binary-info"></div>
                    </div>
                    <div class="sidebar-section">
                        <h3>Search</h3>
                        <div class="search-container">
                            <input type="text" id="search-input" placeholder="Search functions, imports, etc.">
                        </div>
                        <div class="filter-options">
                            <div class="checkbox-item">
                                <input type="checkbox" id="filter-func" checked>
                                <label for="filter-func">Functions</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="filter-import" checked>
                                <label for="filter-import">Imports</label>
                            </div>
                        </div>
                    </div>
                    <div class="sidebar-section">
                        <h3>Selected Node</h3>
                        <div id="node-info">Click a node to see details</div>
                    </div>
                    <div class="sidebar-section">
                        <h3>Statistics</h3>
                        <div id="stats-info"></div>
                    </div>
                </div>
            </div>
            <div class="tooltip" id="graph-tooltip"></div>
            
            <script>
                // Graph data will be inserted here
                const graphData = GRAPH_DATA_PLACEHOLDER;
                const binaryInfo = BINARY_INFO_PLACEHOLDER;
                
                // Populate binary info
                document.getElementById('binary-info').innerHTML = `
                    <div class="info-item"><strong>Name:</strong> ${binaryInfo.name}</div>
                    <div class="info-item"><strong>Architecture:</strong> ${binaryInfo.proc_type}</div>
                    <div class="info-item"><strong>Functions:</strong> ${binaryInfo.function_count}</div>
                    <div class="info-item"><strong>Imports:</strong> ${binaryInfo.import_count}</div>
                    <div class="info-item"><strong>Exports:</strong> ${binaryInfo.export_count}</div>
                    <div class="info-item"><strong>Strings:</strong> ${binaryInfo.string_count}</div>
                `;
                
                // Populate stats info
                document.getElementById('stats-info').innerHTML = `
                    <div class="info-item"><strong>Nodes:</strong> ${graphData.nodes.length}</div>
                    <div class="info-item"><strong>Edges:</strong> ${graphData.links.length}</div>
                    <div class="info-item"><strong>Average degree:</strong> ${(graphData.links.length * 2 / graphData.nodes.length).toFixed(2)}</div>
                `;
                
                // Update title
                document.getElementById('title').textContent = `Blackfyre: ${binaryInfo.name}`;
                
                // D3.js force-directed graph
                const width = document.getElementById('graph').clientWidth;
                const height = document.getElementById('graph').clientHeight;
                
                // Create SVG
                const svg = d3.select("#graph")
                    .append("svg")
                    .attr("width", "100%")
                    .attr("height", "100%")
                    .attr("viewBox", [0, 0, width, height]);
                
                // Add zoom behavior
                const zoom = d3.zoom()
                    .scaleExtent([0.1, 8])
                    .on("zoom", (event) => {
                        g.attr("transform", event.transform);
                    });
                
                // Add container group for zoom
                const g = svg.append("g");
                svg.call(zoom);
                
                // Create simulation
                const simulation = d3.forceSimulation(graphData.nodes)
                    .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
                    .force("charge", d3.forceManyBody().strength(-400))
                    .force("center", d3.forceCenter(width / 2, height / 2))
                    .force("x", d3.forceX(width / 2).strength(0.05))
                    .force("y", d3.forceY(height / 2).strength(0.05));
                
                // Draw links
                const link = g.append("g")
                    .attr("class", "links")
                    .selectAll("line")
                    .data(graphData.links)
                    .enter().append("line")
                    .attr("class", "link")
                    .attr("stroke-width", d => d.value ? Math.sqrt(d.value) : 1);
                
                // Draw nodes
                const node = g.append("g")
                    .attr("class", "nodes")
                    .selectAll("g")
                    .data(graphData.nodes)
                    .enter().append("g")
                    .attr("class", "node")
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended));
                
                // Add circles to nodes
                node.append("circle")
                    .attr("r", d => d.type === "import" ? 5 : 8)
                    .attr("fill", d => d.color)
                    .on("mouseover", showTooltip)
                    .on("mouseout", hideTooltip)
                    .on("click", showNodeDetails);
                
                // Add text labels to nodes
                node.append("text")
                    .attr("dx", 12)
                    .attr("dy", ".35em")
                    .text(d => d.label)
                    .style("font-size", "10px")
                    .style("pointer-events", "none")
                    .style("fill", "#333");
                
                // Tooltip functions
                function showTooltip(event, d) {
                    const tooltip = d3.select("#graph-tooltip");
                    tooltip.html(`<strong>${d.name}</strong><br>Type: ${d.type}<br>Address: 0x${d.id.toString(16)}`);
                    tooltip.style("opacity", 0.9);
                    tooltip.style("left", (event.pageX + 10) + "px")
                          .style("top", (event.pageY - 10) + "px");
                }
                
                function hideTooltip() {
                    d3.select("#graph-tooltip").style("opacity", 0);
                }
                
                // Node details function
                function showNodeDetails(event, d) {
                    const nodeInfo = document.getElementById('node-info');
                    
                    let html = `
                        <p><strong>Name:</strong> ${d.name}</p>
                        <p><strong>Address:</strong> 0x${d.id.toString(16)}</p>
                        <p><strong>Type:</strong> ${d.type}</p>
                    `;
                    
                    if (d.type === "function") {
                        html += `
                            <p><strong>Segment:</strong> ${d.segment || "N/A"}</p>
                            <p><strong>Calls out:</strong> ${d.outDegree}</p>
                            <p><strong>Called by:</strong> ${d.inDegree}</p>
                        `;
                    } else if (d.type === "import") {
                        html += `
                            <p><strong>Library:</strong> ${d.library || "N/A"}</p>
                            <p><strong>Called by:</strong> ${d.inDegree}</p>
                        `;
                    }
                    
                    nodeInfo.innerHTML = html;
                    
                    // Highlight the node and its connections
                    highlightNode(d);
                }
                
                // Highlight selected node and its connections
                function highlightNode(d) {
                    // Reset all nodes and links
                    node.selectAll("circle").attr("stroke", null).attr("stroke-width", 1.5);
                    link.style("stroke", "#999").style("stroke-width", 1);
                    
                    // Highlight selected node
                    node.filter(n => n.id === d.id)
                        .select("circle")
                        .attr("stroke", "#000")
                        .attr("stroke-width", 3);
                    
                    // Highlight connected links and nodes
                    const connectedNodeIds = new Set();
                    
                    link.style("stroke", l => {
                        if (l.source.id === d.id || l.target.id === d.id) {
                            // Add connected nodes to set
                            connectedNodeIds.add(l.source.id === d.id ? l.target.id : l.source.id);
                            return "#000";
                        }
                        return "#999";
                    }).style("stroke-width", l => {
                        return (l.source.id === d.id || l.target.id === d.id) ? 2 : 1;
                    });
                    
                    // Highlight connected nodes
                    node.filter(n => connectedNodeIds.has(n.id))
                        .select("circle")
                        .attr("stroke", "#666")
                        .attr("stroke-width", 2);
                }
                
                // Search function
                document.getElementById('search-input').addEventListener('input', function(e) {
                    const searchTerm = e.target.value.toLowerCase();
                    const showFunctions = document.getElementById('filter-func').checked;
                    const showImports = document.getElementById('filter-import').checked;
                    
                    if (!searchTerm) {
                        // If search is empty, restore all nodes based on filters
                        node.style("opacity", n => {
                            if ((n.type === "function" && showFunctions) || 
                                (n.type === "import" && showImports)) {
                                return 1;
                            }
                            return 0.2;
                        });
                        link.style("opacity", 0.6);
                        return;
                    }
                    
                    // Filter nodes based on search term and type filters
                    const matchingNodeIds = new Set();
                    
                    node.style("opacity", n => {
                        const matchesSearch = n.name.toLowerCase().includes(searchTerm);
                        const matchesType = (n.type === "function" && showFunctions) || 
                                          (n.type === "import" && showImports);
                        
                        if (matchesSearch && matchesType) {
                            matchingNodeIds.add(n.id);
                            return 1;
                        }
                        
                        return 0.1;
                    });
                    
                    // Only show links between matching nodes
                    link.style("opacity", l => {
                        if (matchingNodeIds.has(l.source.id) && matchingNodeIds.has(l.target.id)) {
                            return 0.6;
                        }
                        return 0.05;
                    });
                });
                
                // Filter checkboxes
                document.getElementById('filter-func').addEventListener('change', updateFilters);
                document.getElementById('filter-import').addEventListener('change', updateFilters);
                
                function updateFilters() {
                    const showFunctions = document.getElementById('filter-func').checked;
                    const showImports = document.getElementById('filter-import').checked;
                    
                    // Update node visibility
                    node.style("opacity", n => {
                        if ((n.type === "function" && showFunctions) || 
                            (n.type === "import" && showImports)) {
                            return 1;
                        }
                        return 0.1;
                    });
                    
                    // Update link visibility
                    link.style("opacity", l => {
                        const sourceVisible = (l.source.type === "function" && showFunctions) || 
                                           (l.source.type === "import" && showImports);
                        const targetVisible = (l.target.type === "function" && showFunctions) || 
                                           (l.target.type === "import" && showImports);
                                           
                        if (sourceVisible && targetVisible) {
                            return 0.6;
                        }
                        return 0.05;
                    });
                }
                
                // Zoom control buttons
                document.getElementById('zoom-in').addEventListener('click', () => {
                    svg.transition().call(zoom.scaleBy, 1.3);
                });
                
                document.getElementById('zoom-out').addEventListener('click', () => {
                    svg.transition().call(zoom.scaleBy, 0.7);
                });
                
                document.getElementById('reset-view').addEventListener('click', () => {
                    svg.transition().call(zoom.transform, d3.zoomIdentity);
                });
                
                // Force simulation tick
                simulation.on("tick", () => {
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);
                    
                    node.attr("transform", d => `translate(${d.x},${d.y})`);
                });
                
                function dragstarted(event) {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    event.subject.fx = event.subject.x;
                    event.subject.fy = event.subject.y;
                }
                
                function dragged(event) {
                    event.subject.fx = event.x;
                    event.subject.fy = event.y;
                }
                
                function dragended(event) {
                    if (!event.active) simulation.alphaTarget(0);
                    event.subject.fx = null;
                    event.subject.fy = null;
                }
            </script>
        </body>
        </html>
        """
    
    @classmethod
    def visualize_binary(cls, binary_context, max_nodes=200):
        """Create an interactive visualization of the binary
        
        Args:
            binary_context: A BinaryContext object
            max_nodes: Maximum number of nodes to display
        
        Returns:
            Path to the generated HTML file
        """
        # Prepare graph data
        nodes = []
        links = []
        
        # Count incoming edges for each node (how many times it's called)
        in_degree = {}
        for addr, func in binary_context.function_context_dict.items():
            for callee in func.callees:
                in_degree[callee] = in_degree.get(callee, 0) + 1
        
        # Track nodes we've included
        included_nodes = set()
        
        # Add most connected functions first
        functions = sorted(
            binary_context.function_context_dict.items(), 
            key=lambda x: len(x[1].callees) + in_degree.get(x[0], 0), 
            reverse=True
        )
        
        # Add functions (limit to max_nodes - imports)
        import_count = min(50, len(binary_context.import_symbols))
        function_limit = max_nodes - import_count
        
        for i, (addr, func) in enumerate(functions):
            if i >= function_limit:
                break
                
            # Add function node
            nodes.append({
                "id": addr,
                "name": func.name,
                "label": func.name[:20] + ("..." if len(func.name) > 20 else ""),
                "type": "function",
                "segment": func.segment_name,
                "color": "#4285F4",  # Blue for functions
                "outDegree": len(func.callees),
                "inDegree": in_degree.get(addr, 0)
            })
            
            included_nodes.add(addr)
        
        # Add most referenced imports
        import_refs = [(imp, in_degree.get(imp.address, 0)) for imp in binary_context.import_symbols]
        import_refs.sort(key=lambda x: x[1], reverse=True)
        
        for i, (imp, ref_count) in enumerate(import_refs):
            if i >= import_count:
                break
                
            # Add import node
            nodes.append({
                "id": imp.address,
                "name": imp.name,
                "label": imp.name[:15] + ("..." if len(imp.name) > 15 else ""),
                "type": "import",
                "library": imp.library_name,
                "color": "#EA4335",  # Red for imports
                "inDegree": ref_count,
                "outDegree": 0
            })
            
            included_nodes.add(imp.address)
        
        # Add links between included nodes
        for addr, func in binary_context.function_context_dict.items():
            if addr in included_nodes:
                for callee in func.callees:
                    if callee in included_nodes:
                        links.append({
                            "source": addr,
                            "target": callee
                        })
        
        # Create graph data
        graph_data = {"nodes": nodes, "links": links}
        
        # Create binary info
        binary_info = {
            "name": binary_context.name,
            "proc_type": str(binary_context.proc_type),
            "function_count": len(binary_context.function_context_dict),
            "import_count": len(binary_context.import_symbols),
            "export_count": len(binary_context.export_symbols),
            "string_count": len(binary_context.string_refs)
        }
        
        # Generate HTML
        html = cls._create_html_template()
        html = html.replace("GRAPH_DATA_PLACEHOLDER", json.dumps(graph_data))
        html = html.replace("BINARY_INFO_PLACEHOLDER", json.dumps(binary_info))
        html = html.replace("BINARY_NAME_PLACEHOLDER", binary_context.name)
        
        # Write to temp file and open in browser
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
            f.write(html)
            filename = f.name
        
        webbrowser.open('file://' + os.path.abspath(filename))
        
        return filename
