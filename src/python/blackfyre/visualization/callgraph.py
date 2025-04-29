import networkx as nx
import matplotlib.pyplot as plt

class CallGraph:
    def __init__(self, binary_context, filter_imports=False):
        """Create a call graph from a binary context
        
        Args:
            binary_context: A BinaryContext object
            filter_imports: Whether to exclude imported functions
        """
        self.binary_context = binary_context
        self.filter_imports = filter_imports
        self.graph = self._build_graph()
        
    def _build_graph(self):
        """Build a NetworkX graph from the caller-callee relationships"""
        G = nx.DiGraph()
        
        # Add nodes for each function
        for addr, func in self.binary_context.function_context_dict.items():
            # Skip imports if filtering
            if self.filter_imports and func.is_thunk:
                continue
                
            G.add_node(addr, name=func.name, is_import=func.is_thunk)
        
        # Add edges for caller-callee relationships
        for caller_addr, func in self.binary_context.function_context_dict.items():
            if self.filter_imports and func.is_thunk:
                continue
                
            for callee_addr in func.callees:
                # Check if callee exists in our function dictionary
                # It might not if it's an external function and we're filtering
                if callee_addr in self.binary_context.function_context_dict:
                    callee = self.binary_context.function_context_dict[callee_addr]
                    if not (self.filter_imports and callee.is_thunk):
                        G.add_edge(caller_addr, callee_addr)
        
        return G
    
    def plot(self, filename=None, show=True, max_nodes=100):
        """Plot the call graph
        
        Args:
            filename: If provided, save the image to this path
            show: Whether to display the plot
            max_nodes: Maximum number of nodes to display (for readability)
        """
        if len(self.graph) > max_nodes:
            print(f"Warning: Graph has {len(self.graph)} nodes. Showing only the top {max_nodes} by degree.")
            # Take the most connected nodes
            degrees = dict(self.graph.degree())
            top_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
            top_node_addrs = [addr for addr, _ in top_nodes]
            subgraph = self.graph.subgraph(top_node_addrs)
        else:
            subgraph = self.graph
        
        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(subgraph, seed=42)
        
        # Draw nodes
        function_dict = self.binary_context.function_context_dict
        node_labels = {addr: f"{function_dict[addr].name}\n0x{addr:x}" for addr in subgraph.nodes if addr in function_dict}
        
        # Color imports differently
        node_colors = ['lightcoral' if subgraph.nodes[addr].get('is_import', False) else 'lightblue' 
                      for addr in subgraph.nodes]
        
        nx.draw_networkx_nodes(subgraph, pos, node_size=700, node_color=node_colors, alpha=0.8)
        nx.draw_networkx_labels(subgraph, pos, labels=node_labels, font_size=8)
        
        # Draw edges
        nx.draw_networkx_edges(subgraph, pos, arrows=True, alpha=0.5)
        
        plt.title(f"Call Graph: {self.binary_context.name}")
        plt.axis('off')
        
        if filename:
            plt.savefig(filename)
        
        if show:
            plt.show()
        else:
            plt.close()
        
    def to_graphviz(self, filename=None, max_nodes=200):
        """Export the graph to GraphViz DOT format
        
        Args:
            filename: If provided, save the DOT file to this path
            max_nodes: Maximum number of nodes to include
        
        Returns:
            The DOT representation as a string
        """
        try:
            from networkx.drawing.nx_agraph import to_agraph
            
            # Limit nodes if necessary
            if len(self.graph) > max_nodes:
                print(f"Warning: Graph has {len(self.graph)} nodes. Including only the top {max_nodes} by degree.")
                degrees = dict(self.graph.degree())
                top_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
                top_node_addrs = [addr for addr, _ in top_nodes]
                subgraph = self.graph.subgraph(top_node_addrs)
            else:
                subgraph = self.graph
            
            A = to_agraph(subgraph)
            function_dict = self.binary_context.function_context_dict
            
            # Set node attributes
            for node in A.nodes():
                addr = int(node)
                if addr in function_dict:
                    func = function_dict[addr]
                    node.attr['label'] = f"{func.name}\n0x{addr:x}"
                    node.attr['shape'] = 'box'
                    node.attr['style'] = 'filled'
                    
                    # Color imports differently
                    if func.is_thunk:
                        node.attr['fillcolor'] = 'lightcoral'
                    else:
                        node.attr['fillcolor'] = 'lightblue'
            
            A.graph_attr['label'] = f"Call Graph: {self.binary_context.name}"
            
            if filename:
                A.write(filename)
            
            return A.to_string()
        except ImportError:
            print("Error: PyGraphviz not installed. Unable to create DOT file.")
            return None
