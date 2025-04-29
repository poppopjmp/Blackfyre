import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

class ControlFlowGraph:
    def __init__(self, function_context):
        """Create a control flow graph from a function context
        
        Args:
            function_context: A FunctionContext object
        """
        self.function_context = function_context
        self.graph = self._build_graph()
        
    def _build_graph(self):
        """Build a NetworkX graph from the basic blocks"""
        G = nx.DiGraph()
        
        # Add nodes for each basic block
        for bb in self.function_context.basic_block_contexts:
            G.add_node(bb.start_address, 
                       end_address=bb.end_address, 
                       size=bb.end_address - bb.start_address)
        
        # Add edges based on control flow
        # This is a simplified version that just connects blocks sequentially
        blocks_sorted = sorted(self.function_context.basic_block_contexts, 
                              key=lambda bb: bb.start_address)
        
        for i in range(len(blocks_sorted) - 1):
            current_block = blocks_sorted[i]
            next_block = blocks_sorted[i+1]
            
            # In a real implementation, we would analyze control flow instructions
            # to determine actual edges between basic blocks
            G.add_edge(current_block.start_address, next_block.start_address)
            
        return G
    
    def plot(self, filename=None, show=True):
        """Plot the control flow graph
        
        Args:
            filename: If provided, save the image to this path
            show: Whether to display the plot
        """
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(self.graph)
        
        # Draw nodes
        node_labels = {addr: f"0x{addr:x}" for addr in self.graph.nodes}
        nx.draw_networkx_nodes(self.graph, pos, node_size=700, node_color='lightblue')
        nx.draw_networkx_labels(self.graph, pos, labels=node_labels)
        
        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, arrows=True)
        
        plt.title(f"Control Flow Graph: {self.function_context.name}")
        plt.axis('off')
        
        if filename:
            plt.savefig(filename)
        
        if show:
            plt.show()
        else:
            plt.close()
