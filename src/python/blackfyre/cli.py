import click
import os
import json
import re
from pathlib import Path
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

# Command groups for better organization
@click.group()
def cli():
    """Blackfyre CLI for binary analysis"""
    pass

# ==================== BASIC ANALYSIS COMMANDS ====================
@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--stats', is_flag=True, help='Show binary statistics')
@click.option('--list-functions', is_flag=True, help='List all functions')
def analyze(bcc_file, stats, list_functions):
    """Analyze a BCC file"""
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    if stats:
        click.echo(f"Binary name: {binary_context.name}")
        click.echo(f"Architecture: {binary_context.proc_type}")
        click.echo(f"Function count: {len(binary_context.function_context_dict)}")
        click.echo(f"Import count: {len(binary_context.import_symbols)}")
        click.echo(f"Export count: {len(binary_context.export_symbols)}")
        click.echo(f"String count: {len(binary_context.string_refs)}")
    
    if list_functions:
        for addr, func in binary_context.function_context_dict.items():
            click.echo(f"0x{addr:x}: {func.name}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.argument('function_addr', type=str)
def analyze_data_flow(bcc_file, function_addr):
    """Analyze data flow in a function using VEX IR"""
    from blackfyre.analysis.vex_analysis import DataFlowAnalyzer
    
    # Parse function address (convert from hex if needed)
    addr = int(function_addr, 16) if function_addr.startswith('0x') else int(function_addr)
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Create analyzer and run analysis
    analyzer = DataFlowAnalyzer(binary_context)
    try:
        results = analyzer.analyze_function(addr)
        
        # Print results
        click.echo(f"\nData Flow Analysis for {results['name']} (0x{results['address']:x}):")
        
        click.echo("\nRegister Usage:")
        click.echo(f"- Reads: {', '.join(results['register_usage']['reads'][:10])}{'...' if len(results['register_usage']['reads']) > 10 else ''}")
        click.echo(f"- Writes: {', '.join(results['register_usage']['writes'][:10])}{'...' if len(results['register_usage']['writes']) > 10 else ''}")
        click.echo(f"- Read+Write: {', '.join(results['register_usage']['read_write'][:10])}{'...' if len(results['register_usage']['read_write']) > 10 else ''}")
        
        click.echo("\nMemory Access:")
        click.echo(f"- Loads: {results['memory_access']['load_count']}")
        click.echo(f"- Stores: {results['memory_access']['store_count']}")
        
        click.echo("\nReturn Information:")
        click.echo(f"- Has Return: {results['return_value']['has_return']}")
        click.echo(f"- Return Register: {results['return_value']['return_register']}")
        
    except Exception as e:
        click.echo(f"Error analyzing function: {e}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def export_json(bcc_file, output):
    """Export binary data to JSON format for external analysis"""
    import json
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Set default output path if not provided
    if not output:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output = f"{base_name}.json"
    
    click.echo(f"Exporting {binary_context.name} to JSON...")
    
    # Create JSON structure
    binary_data = {
        "metadata": {
            "name": binary_context.name,
            "architecture": str(binary_context.proc_type),
            "file_type": str(binary_context.file_type),
            "sha256_hash": binary_context.sha256_hash,
            "function_count": len(binary_context.function_context_dict),
            "import_count": len(binary_context.import_symbols),
            "export_count": len(binary_context.export_symbols),
            "string_count": len(binary_context.string_refs)
        },
        "functions": {},
        "imports": [],
        "exports": [],
        "strings": {}
    }
    
    # Add functions
    for addr, func in binary_context.function_context_dict.items():
        binary_data["functions"][hex(addr)] = {
            "name": func.name,
            "start_address": hex(func.start_address),
            "end_address": hex(func.end_address),
            "size": func.end_address - func.start_address,
            "is_thunk": func.is_thunk,
            "callees": [hex(callee) for callee in func.callees] if hasattr(func, "callees") else [],
            "basic_block_count": len(func.basic_block_contexts),
            "instruction_count": func.total_instructions
        }
    
    # Add imports
    for imp in binary_context.import_symbols:
        binary_data["imports"].append({
            "name": imp.name,
            "library": imp.library_name,
            "address": hex(imp.address)
        })
    
    # Add exports
    for exp in binary_context.export_symbols:
        binary_data["exports"].append({
            "name": exp.name,
            "address": hex(exp.address)
        })
    
    # Add strings
    binary_data["strings"] = {hex(addr): value for addr, value in binary_context.string_refs.items()}
    
    # Write to file
    with open(output, 'w') as f:
        json.dump(binary_data, f, indent=2)
    
    click.echo(f"Binary exported to {output}")

# ==================== DIFF & COMPARISON COMMANDS ====================
@cli.command()
@click.argument('original_bcc', type=click.Path(exists=True))
@click.argument('updated_bcc', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for diff report')
def diff(original_bcc, updated_bcc, output):
    """Compare two BCC files to identify changes"""
    from blackfyre.analysis.differential import BinaryDiff
    
    # Load binary contexts
    original_context = BinaryContext.load_from_file(original_bcc)
    updated_context = BinaryContext.load_from_file(updated_bcc)
    
    # Create diff
    differ = BinaryDiff(original_context, updated_context)
    
    # Generate report
    if not output:
        # Default output path if not provided
        output = f"{os.path.basename(original_bcc)}_vs_{os.path.basename(updated_bcc)}_diff.md"
    
    report = differ.generate_report(output)
    click.echo(f"Diff report generated and saved to {output}")
    
    # Print a summary to console
    metadata = differ.compare_metadata()
    functions = differ.compare_functions()
    security = differ.analyze_security_implications()
    
    click.echo("\nDiff Summary:")
    click.echo(f"- File size change: {metadata['file_size'].get('diff', 'N/A')} bytes")
    click.echo(f"- Added functions: {functions['added_functions']['count']}")
    click.echo(f"- Modified functions: {functions['modified_functions']['count']}")
    click.echo(f"- Security findings: {security['total_findings']}")

@cli.command()
@click.argument('original_bcc', type=click.Path(exists=True))
@click.argument('comparison_bcc', type=click.Path(exists=True))
@click.option('--threshold', '-t', type=float, default=0.8, help='Similarity threshold (0-1)')
@click.option('--max-matches', '-n', type=int, default=20, help='Maximum number of matches to display')
@click.option('--output', '-o', type=click.Path(), help='Output HTML file path')
def compare_binaries(original_bcc, comparison_bcc, threshold, max_matches, output):
    """Compare functions between two binaries to find similarities"""
    from blackfyre.ml.similarity import BinarySimilarityDetector
    
    # Load binary contexts
    original_context = BinaryContext.load_from_file(original_bcc)
    comparison_context = BinaryContext.load_from_file(comparison_bcc)
    
    click.echo(f"Comparing {original_context.name} with {comparison_context.name}...")
    
    # Initialize similarity detector
    detector = BinarySimilarityDetector(original_context, comparison_context)
    
    # Find similar functions
    try:
        matches = detector.find_similar_functions(threshold)
        
        # Calculate overall similarity score
        similarity_score = detector.compute_binary_similarity_score()
        
        click.echo(f"\nOverall similarity score: {similarity_score:.4f}")
        click.echo(f"Found {len(matches)} function matches with similarity >= {threshold}:")
        
        # Display top matches
        for i, match in enumerate(matches[:max_matches], 1):
            func_a = match["function_a"]
            func_b = match["function_b"]
            
            click.echo(f"\n{i}. Match (similarity: {match['similarity']:.4f}):")
            click.echo(f"   Original:   {func_a['name']} (0x{func_a['address']:x}, {func_a['size']} bytes)")
            click.echo(f"   Comparison: {func_b['name']} (0x{func_b['address']:x}, {func_b['size']} bytes)")
        
        # Generate visual diff if output is specified
        if output:
            from blackfyre.visualization.binary_diff import BinaryComparisonViewer
            html_file = BinaryComparisonViewer.visualize_diff(original_context, comparison_context)
            
            # Copy to the specified output location
            import shutil
            shutil.copy(html_file, output)
            click.echo(f"Visual diff saved to {output}")
            
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.argument('function_addr', type=str)
@click.option('--output', '-o', type=click.Path(), help='Output file for visualization')
@click.option('--format', type=click.Choice(['png', 'svg', 'pdf']), default='png', help='Output format')
def visualize(bcc_file, function_addr, output, format):
    """Visualize a function's control flow graph"""
    from blackfyre.visualization.cfg import ControlFlowGraph
    
    # Parse function address (convert from hex if needed)
    addr = int(function_addr, 16) if function_addr.startswith('0x') else int(function_addr)
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Get function
    if addr not in binary_context.function_context_dict:
        click.echo(f"Error: Function not found at address {function_addr}")
        return
    
    function = binary_context.function_context_dict[addr]
    
    # Create and display CFG
    cfg = ControlFlowGraph(function)
    
    # Set default output path if not provided
    if output:
        cfg.plot(filename=f"{output}.{format}", show=False)
        click.echo(f"Control flow graph saved to {output}.{format}")
    else:
        cfg.plot()

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--max-nodes', type=int, default=200, help='Maximum number of nodes to display')
@click.option('--output', '-o', type=click.Path(), help='Output HTML file path')
def interactive(bcc_file, max_nodes, output):
    """Generate interactive web visualization of the binary"""
    from blackfyre.visualization.web import InteractiveVisualization
    
    # Load the binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Set custom output if provided
    if output:
        # Generate HTML content
        html_file = InteractiveVisualization.visualize_binary(binary_context, max_nodes)
        
        # Copy to the specified output location
        import shutil
        shutil.copy(html_file, output)
        click.echo(f"Interactive visualization saved to {output}")
    else:
        # Generate and open visualization in browser
        html_file = InteractiveVisualization.visualize_binary(binary_context, max_nodes)
        click.echo(f"Interactive visualization opened in browser and saved to {html_file}")

# ==================== RULE GENERATION COMMANDS ====================
@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for YARA rules')
@click.option('--min-string-length', type=int, default=8, help='Minimum string length to consider')
@click.option('--max-rules', type=int, default=50, help='Maximum number of rules to generate')
def generate_yara(bcc_file, output, min_string_length, max_rules):
    """Generate YARA rules from a BCC file"""
    from blackfyre.integrations.yara.rule_generator import YaraRuleGenerator
    
    binary_context = BinaryContext.load_from_file(bcc_file)
    generator = YaraRuleGenerator(binary_context)
    
    # Set default output path if not provided
    if not output:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output = f"{base_name}_rules.yar"
    
    # Generate rules
    rules = generator.generate_all_rules(output)
    click.echo(f"Generated YARA rules and saved to {output}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for threat report')
@click.option('--stix', is_flag=True, help='Include STIX data in the report')
def threat_analysis(bcc_file, output, stix):
    """Analyze a binary for potential threats using threat intelligence"""
    from blackfyre.integrations.threat_intel.analyzer import ThreatIntelligenceAnalyzer
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Create analyzer and run analysis
    analyzer = ThreatIntelligenceAnalyzer(binary_context)
    
    # Set default output path if not provided
    if not output:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output = f"{base_name}_threat_report.md"
    
    # Generate report
    report = analyzer.generate_report(output, include_stix=stix)
    
    # Display summary on console
    analysis = analyzer.analyze()
    click.echo("\nThreat Analysis Summary:")
    click.echo(f"- Binary: {analysis['binary']['name']}")
    click.echo(f"- Threat Assessment: {analysis['threat_assessment'].upper()}")
    click.echo(f"- Threat Score: {analysis['threat_score']}")
    click.echo(f"- Total Findings: {analysis['total_findings']}")
    click.echo(f"- Report saved to: {output}")

# ==================== MACHINE LEARNING COMMANDS ====================
@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output CSV file for features')
def extract_features(bcc_file, output):
    """Extract machine learning features from functions"""
    import csv
    from blackfyre.ml.feature_extractor import FunctionFeatureExtractor
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Create feature extractor
    extractor = FunctionFeatureExtractor(binary_context)
    
    # Extract features
    click.echo("Extracting features from functions...")
    features = extractor.extract_features_for_all_functions()
    
    # Set default output path if not provided
    if not output:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output = f"{base_name}_features.csv"
    
    # Write features to CSV
    if features:
        with open(output, 'w', newline='') as f:
            # Get all feature names from the first result
            fieldnames = list(features[0].keys())
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(features)
            
        click.echo(f"Extracted features for {len(features)} functions and saved to {output}")
    else:
        click.echo("No features extracted")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.argument('function_addr', type=str)
@click.option('--threshold', '-t', type=float, default=0.8, help='Similarity threshold (0-1)')
@click.option('--max-results', '-n', type=int, default=10, help='Maximum number of results')
def find_similar(bcc_file, function_addr, threshold, max_results):
    """Find functions similar to a target function"""
    from blackfyre.ml.similarity import FunctionSimilarityDetector
    
    # Parse function address (convert from hex if needed)
    addr = int(function_addr, 16) if function_addr.startswith('0x') else int(function_addr)
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Initialize similarity detector
    detector = FunctionSimilarityDetector(binary_context)
    
    # Find similar functions
    try:
        click.echo(f"Finding functions similar to {binary_context.function_context_dict[addr].name} (0x{addr:x})...")
        results = detector.find_similar_functions(addr, threshold, max_results)
        
        if not results:
            click.echo("No similar functions found.")
            return
            
        click.echo(f"\nFound {len(results)} similar functions:")
        for i, result in enumerate(results, 1):
            click.echo(f"{i}. {result['name']} (0x{result['address']:x})")
            click.echo(f"   Similarity: {result['similarity']:.4f}")
            click.echo(f"   Size: {result['size']} bytes")
            
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.argument('labeled_data_dir', type=click.Path(exists=True))
@click.option('--model-output', '-o', type=click.Path(), help='Output path for trained model')
@click.option('--test-size', type=float, default=0.2, help='Proportion of data to use for testing')
def train_classifier(labeled_data_dir, model_output, test_size):
    """Train a function classifier using labeled data
    
    Labeled data format: Directory containing BCC files in subdirectories named by class
    Example: labeled_data/crypto/, labeled_data/network/, etc.
    """
    import glob
    from blackfyre.ml.model import FunctionClassifier
    from blackfyre.ml.feature_extractor import FunctionFeatureExtractor
    
    # Find BCC files in the directory structure
    class_dirs = [d for d in os.listdir(labeled_data_dir) 
                 if os.path.isdir(os.path.join(labeled_data_dir, d))]
    
    if not class_dirs:
        click.echo("Error: No class directories found in the labeled data directory")
        return
    
    click.echo(f"Found {len(class_dirs)} classes: {', '.join(class_dirs)}")
    
    # Collect features and labels
    all_features = []
    all_labels = []
    
    for class_name in class_dirs:
        class_dir = os.path.join(labeled_data_dir, class_name)
        bcc_files = glob.glob(os.path.join(class_dir, "*.bcc"))
        
        if not bcc_files:
            click.echo(f"Warning: No BCC files found in {class_dir}")
            continue
            
        click.echo(f"Processing {len(bcc_files)} files for class '{class_name}'...")
        
        for bcc_file in bcc_files:
            try:
                # Load binary context
                binary_context = BinaryContext.load_from_file(bcc_file)
                
                # Extract features for all functions
                extractor = FunctionFeatureExtractor(binary_context)
                features = extractor.extract_features_for_all_functions()
                
                # Add to dataset
                all_features.extend(features)
                all_labels.extend([class_name] * len(features))
                
            except Exception as e:
                click.echo(f"Error processing {bcc_file}: {e}")
    
    if not all_features:
        click.echo("Error: No features extracted from the labeled data")
        return
        
    click.echo(f"\nCollected {len(all_features)} labeled functions")
    
    # Train classifier
    classifier = FunctionClassifier()
    metrics = classifier.train(all_features, all_labels, test_size=test_size)
    
    click.echo(f"\nTraining results:")
    click.echo(f"- Accuracy: {metrics['accuracy']:.4f}")
    click.echo(f"- Precision: {metrics['precision']:.4f}")
    click.echo(f"- Recall: {metrics['recall']:.4f}")
    click.echo(f"- F1 Score: {metrics['f1']:.4f}")
    
    # Save model if requested
    if model_output:
        classifier.save_model(model_output)
        click.echo(f"\nModel saved to {model_output}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.argument('model_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output JSON file for predictions')
@click.option('--min-confidence', type=float, default=0.6, help='Minimum confidence threshold')
def classify_functions(bcc_file, model_file, output, min_confidence):
    """Classify functions in a binary using a trained model"""
    import json
    from blackfyre.ml.model import FunctionClassifier
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Load model
    try:
        classifier = FunctionClassifier.load_model(model_file)
    except Exception as e:
        click.echo(f"Error loading model: {e}")
        return
    
    # Run classification
    click.echo(f"Classifying functions in {binary_context.name}...")
    predictions = classifier.predict_functions_in_binary(binary_context)
    
    # Filter by confidence
    filtered_predictions = {
        addr: result for addr, result in predictions.items()
        if result["confidence"] >= min_confidence
    }
    
    # Summarize results
    class_counts = {}
    for result in filtered_predictions.values():
        class_name = result["predicted_class"]
        class_counts[class_name] = class_counts.get(class_name, 0) + 1
    
    click.echo(f"\nClassified {len(filtered_predictions)} functions with confidence >= {min_confidence}:")
    for class_name, count in sorted(class_counts.items(), key=lambda x: x[1], reverse=True):
        click.echo(f"- {class_name}: {count} functions")
    
    # Output results if requested
    if output:
        # Convert addresses to strings for JSON serialization
        json_predictions = {
            hex(addr): result for addr, result in filtered_predictions.items()
        }
        
        with open(output, 'w') as f:
            json.dump(json_predictions, f, indent=2)
            
        click.echo(f"\nPredictions saved to {output}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--model', '-m', type=click.Path(exists=True), help='Path to vulnerability classification model')
@click.option('--output', '-o', type=click.Path(), help='Output file for vulnerability report')
def detect_vulnerabilities(bcc_file, model, output):
    """Detect potential vulnerabilities in a binary"""
    from blackfyre.ml.vulnerability import VulnerabilityDetector
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Initialize vulnerability detector
    detector = VulnerabilityDetector(binary_context, model)
    
    click.echo(f"Analyzing {binary_context.name} for potential vulnerabilities...")
    findings = detector.detect_vulnerabilities()
    
    # Generate report
    if not output:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output = f"{base_name}_vulnerabilities.md"
        
    detector.generate_report(findings, output)
    
    # Print summary
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        risk = finding.get("risk", "low")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    click.echo(f"\nVulnerability Summary:")
    click.echo(f"- Total potential vulnerabilities: {len(findings)}")
    click.echo(f"- High risk: {risk_counts.get('high', 0)}")
    click.echo(f"- Medium risk: {risk_counts.get('medium', 0)}")
    click.echo(f"- Low risk: {risk_counts.get('low', 0)}")
    click.echo(f"- Report saved to: {output}")

# ==================== LLM INTEGRATION COMMANDS ====================
@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.argument('function_addr', type=str)
@click.option('--provider', type=str, default="openai", help='LLM provider (openai, anthropic, azure)')
@click.option('--model', type=str, default="gpt-4", help='Model name')
@click.option('--api-key', type=str, help='API key (if not set in environment)')
@click.option('--output', '-o', type=click.Path(), help='Output file for explanation')
def explain_function(bcc_file, function_addr, provider, model, api_key, output):
    """Explain a function using an LLM"""
    import json
    from blackfyre.ml.llm_integration import LLMConfig, LLMProcessor, CodeExplainer
    
    # Parse function address (convert from hex if needed)
    addr = int(function_addr, 16) if function_addr.startswith('0x') else int(function_addr)
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    try:
        # Check if function exists
        if addr not in binary_context.function_context_dict:
            click.echo(f"Error: Function not found at address {function_addr}")
            return
            
        function = binary_context.function_context_dict[addr]
        click.echo(f"Analyzing function {function.name} (0x{addr:x}) using {provider}/{model}...")
        
        # Initialize LLM integration
        llm_config = LLMConfig(provider=provider, model=model, api_key=api_key)
        llm_processor = LLMProcessor(llm_config)
        
        # Initialize code explainer
        explainer = CodeExplainer(binary_context, llm_processor)
        
        # Get function explanation
        explanation = explainer.explain_function(addr)
        
        # Output explanation
        click.echo("\nFunction Explanation:\n")
        click.echo(explanation["explanation"])
        
        # Save to file if requested
        if output:
            if output.lower().endswith('.json'):
                # Save as JSON
                with open(output, 'w') as f:
                    json.dump(explanation, f, indent=2)
            else:
                # Save as text
                with open(output, 'w') as f:
                    f.write(f"# Analysis of {function.name} (0x{addr:x})\n\n")
                    f.write(explanation["explanation"])
                    
            click.echo(f"\nExplanation saved to {output}")
            
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--provider', type=str, default="openai", help='LLM provider (openai, anthropic, azure)')
@click.option('--model', type=str, default="gpt-4", help='Model name')
@click.option('--max-functions', type=int, default=5, help='Maximum functions to analyze')
@click.option('--output', '-o', type=click.Path(), help='Output file for vulnerability report')
def llm_vulnerability_scan(bcc_file, provider, model, max_functions, output):
    """Scan for vulnerabilities using LLM analysis"""
    from blackfyre.ml.llm_integration import LLMConfig, LLMProcessor
    from blackfyre.ml.llm_vulnerability import LLMVulnerabilityAnalyzer
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    try:
        click.echo(f"Scanning {binary_context.name} for vulnerabilities using {provider}/{model}...")
        
        # Initialize LLM integration
        llm_config = LLMConfig(provider=provider, model=model)
        llm_processor = LLMProcessor(llm_config)
        
        # Initialize vulnerability analyzer
        analyzer = LLMVulnerabilityAnalyzer(binary_context, llm_processor)
        
        # Find and analyze suspicious functions
        click.echo(f"Analyzing up to {max_functions} suspicious functions...")
        assessments = analyzer.analyze_suspicious_functions(max_functions)
        
        # Generate report
        if not output:
            base_name = os.path.splitext(os.path.basename(bcc_file))[0]
            output = f"{base_name}_vulnerability_report.md"
            
        report = analyzer.generate_report(assessments, output)
        
        click.echo(f"Analyzed {len(assessments)} potentially vulnerable functions")
        click.echo(f"Report saved to {output}")
        
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for analysis reports')
@click.option('--provider', type=str, default="openai", help='LLM provider (openai, anthropic, azure)')
@click.option('--model', type=str, default="gpt-3.5-turbo", help='Model name')
@click.option('--max-functions', type=int, default=10, help='Maximum functions to analyze')
@click.option('--analysis-types', type=str, default="function_analysis", 
              help='Comma-separated list of analysis types')
@click.option('--no-similarity', is_flag=True, help='Skip similarity analysis')
def analyze_comprehensive(bcc_file, output_dir, provider, model, max_functions, analysis_types, no_similarity):
    """Run comprehensive LLM analysis on a binary"""
    from blackfyre.ml.analysis_manager import LLMAnalysisManager
    from blackfyre.ml.advanced_llm import AdvancedLLMAnalyzer
    from blackfyre.ml.llm_integration import LLMConfig
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Set default output directory if not provided
    if not output_dir:
        base_name = os.path.splitext(os.path.basename(bcc_file))[0]
        output_dir = f"{base_name}_analysis"
    
    try:
        # Initialize LLM configuration
        llm_config = LLMConfig(provider=provider, model=model)
        
        # Initialize LLM analyzer
        llm_analyzer = AdvancedLLMAnalyzer(
            binary_context, 
            llm_config=llm_config,
            cache_dir=os.path.join(output_dir, "cache")
        )
        
        # Initialize analysis manager
        manager = LLMAnalysisManager(
            binary_context, 
            output_dir,
            llm_analyzer=llm_analyzer
        )
        
        # Parse analysis types
        analysis_type_list = [t.strip() for t in analysis_types.split(",")]
        
        click.echo(f"Starting comprehensive analysis of {binary_context.name}")
        click.echo(f"Using {provider}/{model} for analysis")
        click.echo(f"Analyzing up to {max_functions} functions with {', '.join(analysis_type_list)}")
        
        # Run analysis
        result = manager.run_comprehensive_analysis(
            max_functions=max_functions,
            analysis_types=analysis_type_list,
            include_similarity=not no_similarity
        )
        
        click.echo(f"\nAnalysis completed!")
        click.echo(f"Results saved to {result['results_dir']}")
        click.echo(f"  - Binary overview: {result['overview_path']}")
        click.echo(f"  - Analysis summary: {result['summary_path']}")
        
    except Exception as e:
        click.echo(f"Error running analysis: {e}")

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for visualization')
@click.option('--format', type=click.Choice(['png', 'svg', 'pdf']), default='png', help='Output format')
def visualize(bcc_file, function_addr, output, format):
    """Visualize a function's control flow graph"""
    from blackfyre.visualization.cfg import ControlFlowGraph
    
    # Parse function address (convert from hex if needed)
    addr = int(function_addr, 16) if function_addr.startswith('0x') else int(function_addr)
    
    # Load binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Get function
    if addr not in binary_context.function_context_dict:
        click.echo(f"Error: Function not found at address {function_addr}")
        return
    
    function = binary_context.function_context_dict[addr]
    
    # Create and display CFG
    cfg = ControlFlowGraph(function)
    
    # Set default output path if not provided
    if output:
        cfg.plot(filename=f"{output}.{format}", show=False)
        click.echo(f"Control flow graph saved to {output}.{format}")
    else:
        cfg.plot()

@cli.command()
@click.argument('bcc_file', type=click.Path(exists=True))
@click.option('--max-nodes', type=int, default=200, help='Maximum number of nodes to display')
@click.option('--output', '-o', type=click.Path(), help='Output HTML file path')
def interactive(bcc_file, max_nodes, output):
    """Generate interactive web visualization of the binary"""
    from blackfyre.visualization.web import InteractiveVisualization
    
    # Load the binary context
    binary_context = BinaryContext.load_from_file(bcc_file)
    
    # Set custom output if provided
    if output:
        # Generate HTML content
        html_file = InteractiveVisualization.visualize_binary(binary_context, max_nodes)
        
        # Copy to the specified output location
        import shutil
        shutil.copy(html_file, output)
        click.echo(f"Interactive visualization saved to {output}")
    else:
        # Generate and open visualization in browser
        html_file = InteractiveVisualization.visualize_binary(binary_context, max_nodes)
        click.echo(f"Interactive visualization opened in browser and saved to {html_file}")

# ==================== HELPER FUNCTIONS ====================
def generate_binary_summary(binary_context, llm_processor):
    """Generate a summary of the binary using an LLM"""
    # Create a concise description of the binary
    binary_info = {
        "name": binary_context.name,
        "architecture": str(binary_context.proc_type),
        "function_count": len(binary_context.function_context_dict),
        "import_count": len(binary_context.import_symbols),
        "export_count": len(binary_context.export_symbols),
        "string_count": len(binary_context.string_refs),
    }
    
    # Get lists of imports/exports
    import_list = [f"{imp.name} (from {imp.library_name})" 
                  for imp in binary_context.import_symbols[:20]]  # Limit to 20
    export_list = [exp.name for exp in binary_context.export_symbols[:20]]  # Limit to 20
    
    # Get interesting strings (potential indicators of functionality)
    interesting_strings = []
    for addr, string in binary_context.string_refs.items():
        if len(string) > 5 and len(string) < 100:  # Filter out very short/long strings
            interesting_strings.append(string)
    interesting_strings = interesting_strings[:30]  # Limit to 30
    
    # Format the prompt
    system_prompt = """
    You are a binary analysis expert. Your task is to provide a comprehensive summary of a binary
    based on its metadata, imports, exports, and strings. Focus on:
    1. Likely purpose/functionality of the binary
    2. Programming language or framework used
    3. Key capabilities based on imports
    4. Security implications (if any)
    5. Any notable observations
    
    Provide a clear, structured analysis in markdown format.
    """
    
    user_prompt = f"""
    Please analyze this binary and provide a summary:
    
    ## Binary Information
    - Name: {binary_info['name']}
    - Architecture: {binary_info['architecture']}
    - Number of functions: {binary_info['function_count']}
    - Number of imports: {binary_info['import_count']}
    - Number of exports: {binary_info['export_count']}
    - Number of strings: {binary_info['string_count']}
    
    ## Key Imports (up to 20)
    {chr(10).join([f"- {imp}" for imp in import_list])}
    
    ## Key Exports (up to 20)
    {chr(10).join([f"- {exp}" for exp in export_list])}
    
    ## Interesting Strings
    {chr(10).join([f"- \"{s}\"" for s in interesting_strings])}
    
    Please provide a comprehensive analysis of this binary in markdown format,
    including its likely purpose, programming language/framework, capabilities,
    and any security implications.
    """
    
    # Call the LLM
    summary = llm_processor.call_llm_api(user_prompt, system_prompt)
    
    # Format the final output
    final_summary = f"""# Binary Analysis Summary for {binary_info['name']}

## Binary Metadata
- Name: {binary_info['name']}
- Architecture: {binary_info['architecture']}
- Functions: {binary_info['function_count']}
- Imports: {binary_info['import_count']}
- Exports: {binary_info['export_count']}
- Strings: {binary_info['string_count']}

## Analysis

{summary}
"""
    return final_summary

def select_key_functions(binary_context, count=5, name_filter=None):
    """Select key functions from a binary for analysis"""
    functions = []
    
    # Compile regex if filter provided
    name_pattern = None
    if name_filter:
        try:
            name_pattern = re.compile(name_filter, re.IGNORECASE)
        except re.error:
            click.echo(f"Warning: Invalid regex pattern '{name_filter}', ignoring filter")
    
    # First, get main/entry functions
    entry_points = []
    for addr, func in binary_context.function_context_dict.items():
        name = func.name.lower()
        if name == "main" or "_main" in name or "entry" in name or "start" in name:
            entry_points.append(addr)
    
    # Then, get functions with the most callees (complex functions)
    complex_functions = sorted(
        [(addr, len(func.callees)) for addr, func in binary_context.function_context_dict.items()
         if not func.is_thunk],  # Skip thunks
        key=lambda x: x[1],
        reverse=True
    )
    
    # Combine entry points and complex functions, prioritizing entry points
    for addr in entry_points:
        if name_pattern and not name_pattern.search(binary_context.function_context_dict[addr].name):
            continue
        functions.append(addr)
        if len(functions) >= count:
            return functions
    
    # Add remaining complex functions
    for addr, _ in complex_functions:
        if addr not in functions:  # Skip if already added
            if name_pattern and not name_pattern.search(binary_context.function_context_dict[addr].name):
                continue
            functions.append(addr)
            if len(functions) >= count:
                return functions
    
    return functions

def handle_command(command, binary_context, code_explainer, chat_history):
    """Handle special commands in interactive mode"""
    parts = command.split()
    cmd = parts[0].lower()
    
    if cmd == "!help":
        click.echo("\nAvailable commands:")
        click.echo("  !help - Show this help")
        click.echo("  !exit - Exit the session")
        click.echo("  !func <address> - Analyze function at address")
        click.echo("  !list [count] - List functions (default: 10)")
        click.echo("  !imports - Show imports")
        click.echo("  !exports - Show exports")
        click.echo("  !strings [pattern] - Show strings (with optional regex pattern)")
        click.echo("  !find <pattern> - Find functions by name")
    
    elif cmd == "!list":
        count = 10  # Default
        if len(parts) > 1 and parts[1].isdigit():
            count = int(parts[1])
            
        # Get functions sorted by address
        funcs = sorted(
            [(addr, func.name) for addr, func in binary_context.function_context_dict.items()],
            key=lambda x: x[0]
        )
        
        click.echo(f"\nFunctions (showing {min(count, len(funcs))} of {len(funcs)}):")
        for addr, name in funcs[:count]:
            click.echo(f"0x{addr:x}: {name}")
    
    elif cmd == "!func":
        if len(parts) < 2:
            click.echo("Error: Missing function address. Usage: !func <address>")
            return
            
        # Parse address
        try:
            addr = int(parts[1], 16) if parts[1].startswith("0x") else int(parts[1])
                
            if addr not in binary_context.function_context_dict:
                click.echo(f"Error: No function found at address {parts[1]}")
                return
                
            # Get function analysis
            click.echo(f"\nAnalyzing function at {parts[1]}...")
            explanation = code_explainer.explain_function(addr)
            click.echo(f"\n{explanation['explanation']}")
            
            # Update chat history
            func = binary_context.function_context_dict[addr]
            chat_history.append({
                "role": "user", 
                "content": f"Analyze function {func.name} at {parts[1]}"
            })
            chat_history.append({
                "role": "assistant", 
                "content": explanation["explanation"]
            })
            
        except ValueError:
            click.echo(f"Error: Invalid address format: {parts[1]}")
        except Exception as e:
            click.echo(f"Error analyzing function: {e}")
    
    elif cmd == "!imports":
        click.echo(f"\nImports ({len(binary_context.import_symbols)}):")
        for imp in binary_context.import_symbols[:30]:  # Limit to 30
            click.echo(f"{imp.name} (from {imp.library_name})")
        
        if len(binary_context.import_symbols) > 30:
            click.echo(f"... and {len(binary_context.import_symbols) - 30} more")
    
    elif cmd == "!exports":
        click.echo(f"\nExports ({len(binary_context.export_symbols)}):")
        for exp in binary_context.export_symbols[:30]:  # Limit to 30
            click.echo(f"{exp.name}")
        
        if len(binary_context.export_symbols) > 30:
            click.echo(f"... and {len(binary_context.export_symbols) - 30} more")
    
    elif cmd == "!strings":
        # Check for pattern
        pattern = None
        if len(parts) > 1:
            pattern = parts[1]
            
        strings = list(binary_context.string_refs.items())
        
        # Filter by pattern if provided
        if pattern:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                strings = [(addr, s) for addr, s in strings if regex.search(s)]
                click.echo(f"\nStrings matching '{pattern}' ({len(strings)} results):")
            except re.error:
                click.echo(f"Error: Invalid regex pattern")
                return
        else:
            click.echo(f"\nStrings (showing up to 20 of {len(strings)}):")
        
        # Display strings
        for addr, string in strings[:20]:  # Limit to 20
            # Truncate long strings
            if len(string) > 60:
                string = string[:57] + "..."
            click.echo(f"0x{addr:x}: \"{string}\"")
            
        if len(strings) > 20:
            click.echo(f"... and {len(strings) - 20} more")
    
    elif cmd == "!find":
        if len(parts) < 2:
            click.echo("Error: Missing search pattern. Usage: !find <pattern>")
            return
            
        pattern = parts[1]
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = [(addr, func.name) for addr, func in binary_context.function_context_dict.items()
                      if regex.search(func.name)]
            
            click.echo(f"\nFunctions matching '{pattern}' ({len(matches)} results):")
            for addr, name in matches[:20]:  # Limit to 20
                click.echo(f"0x{addr:x}: {name}")
                
            if len(matches) > 20:
                click.echo(f"... and {len(matches) - 20} more")
                
        except re.error:
            click.echo(f"Error: Invalid regex pattern")
    
    else:
        click.echo(f"Unknown command: {cmd}. Type !help for available commands.")

def create_binary_context_summary(binary_context):
    """Create a concise summary of binary context for LLM prompts"""
    # Summarize imports
    import_summary = []
    import_libs = {}
    for imp in binary_context.import_symbols:
        if imp.library_name not in import_libs:
            import_libs[imp.library_name] = []
        import_libs[imp.library_name].append(imp.name)
    
    for lib, funcs in sorted(import_libs.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
        import_summary.append(f"{lib}: {', '.join(funcs[:10])}" + 
                             (f"... and {len(funcs)-10} more" if len(funcs) > 10 else ""))
    
    # Summarize strings - focus on potentially interesting ones
    interesting_strings = []
    string_patterns = [
        r"http[s]?://", r"\.dll", r"\.exe", r"\.so", r"\.dylib",  # URLs and libraries
        r"password", r"user", r"config", r"error", r"fail",       # Common keywords
        r"encryption", r"decrypt", r"key", r"hash", r"crypt"      # Security-related
    ]
    
    for addr, string in binary_context.string_refs.items():
        if any(re.search(pattern, string, re.IGNORECASE) for pattern in string_patterns):
            interesting_strings.append(string)
    
    # Limit strings to a reasonable number
    interesting_strings = interesting_strings[:20]
    
    # Build summary
    summary = f"""
    Name: {binary_context.name}
    Architecture: {binary_context.proc_type}
    Functions: {len(binary_context.function_context_dict)}
    Imports: {len(binary_context.import_symbols)}
    Exports: {len(binary_context.export_symbols)}
    
    Key libraries and functions:
    {chr(10).join(import_summary)}
    
    Interesting strings:
    {chr(10).join([f'"{s}"' for s in interesting_strings])}
    """
    
    return summary

if __name__ == '__main__':
    cli()
