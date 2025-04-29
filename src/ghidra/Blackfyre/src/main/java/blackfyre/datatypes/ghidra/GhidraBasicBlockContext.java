package blackfyre.datatypes.ghidra;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import blackfyre.datatypes.BasicBlockContext;
import blackfyre.datatypes.InstructionContext;
import blackfyre.datatypes.ProcessorType;

public class GhidraBasicBlockContext extends BasicBlockContext{
	
	private Program theCurrentProgram;
	
	private CodeBlock theBasicBlock;
	
	
	public GhidraBasicBlockContext(Program currentProgram, CodeBlock basicBlock, ProcessorType procType)
	{
		theCurrentProgram = currentProgram;
		theBasicBlock = basicBlock;
		theProcType = procType;
	}
	
	@Override
	public boolean initialize()
	{
		if(theIsInitialized)
		{
			return theIsInitialized;
		}
		
		try {
			theStartAddress = getStartAddressFromGhidra();
			theEndAddress = getEndAddressFromGhidra();
			theInstructionContexts = getInstructionContextsFromGhidra();
			
			// Add incoming and outgoing edges
			theIncomingEdges = getIncomingEdgesFromGhidra();
			theOutgoingEdges = getOutgoingEdgesFromGhidra();
			
			// Check if block has calls
			theHasCall = checkHasCallFromGhidra();
			
			theIsInitialized = true;
		} catch (Exception e) {
			System.err.println("Error initializing basic block: " + e.getMessage());
			e.printStackTrace();
			return false;
		}
		
		return theIsInitialized;
	}
	
	private InstructionContext [] getInstructionContextsFromGhidra()
	{
		ArrayList<InstructionContext> instructionContexts = new ArrayList<>();
		
		try {
			AddressSetView addresses = theBasicBlock.getAddresses(true);
			AddressIterator addressIterator = addresses.getAddresses();
			
			while (addressIterator.hasNext()) {
				Address address = addressIterator.next();
				Instruction instruction = theCurrentProgram.getListing().getInstructionAt(address);
				
				if (instruction != null) {
					// Enhanced instruction context with operand analysis
					GhidraInstructionContext instructionContext = new GhidraInstructionContext(
						theCurrentProgram, 
						instruction
					);
					instructionContexts.add(instructionContext);
				}
			}
		} catch (Exception e) {
			System.err.println("Error getting instruction contexts: " + e.getMessage());
			e.printStackTrace();
		}
		
		return instructionContexts.toArray(new InstructionContext[instructionContexts.size()]);
	}
	
	private long[] getIncomingEdgesFromGhidra() {
		ArrayList<Long> incomingEdges = new ArrayList<>();
		
		try {
			var sourceIter = theBasicBlock.getSources();
			while (sourceIter.hasNext()) {
				var sourceRef = sourceIter.next();
				incomingEdges.add(sourceRef.getSourceAddress().getOffset());
			}
		} catch (Exception e) {
			System.err.println("Error getting incoming edges: " + e.getMessage());
			e.printStackTrace();
		}
		
		// Convert to primitive long array
		long[] result = new long[incomingEdges.size()];
		for (int i = 0; i < incomingEdges.size(); i++) {
			result[i] = incomingEdges.get(i);
		}
		
		return result;
	}
	
	private long[] getOutgoingEdgesFromGhidra() {
		ArrayList<Long> outgoingEdges = new ArrayList<>();
		
		try {
			var destIter = theBasicBlock.getDestinations();
			while (destIter.hasNext()) {
				var destRef = destIter.next();
				outgoingEdges.add(destRef.getDestinationAddress().getOffset());
			}
		} catch (Exception e) {
			System.err.println("Error getting outgoing edges: " + e.getMessage());
			e.printStackTrace();
		}
		
		// Convert to primitive long array
		long[] result = new long[outgoingEdges.size()];
		for (int i = 0; i < outgoingEdges.size(); i++) {
			result[i] = outgoingEdges.get(i);
		}
		
		return result;
	}
	
	private boolean checkHasCallFromGhidra() {
		try {
			AddressSetView addresses = theBasicBlock.getAddresses(true);
			AddressIterator addressIterator = addresses.getAddresses();
			
			while (addressIterator.hasNext()) {
				Address address = addressIterator.next();
				Instruction instruction = theCurrentProgram.getListing().getInstructionAt(address);
				
				if (instruction != null && instruction.getFlowType().isCall()) {
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Error checking for calls: " + e.getMessage());
			e.printStackTrace();
		}
		
		return false;
	}
	
	private long getStartAddressFromGhidra()
	{
		return theBasicBlock.getFirstStartAddress().getOffset();
	}
	
	private long getEndAddressFromGhidra()
	{
		return theBasicBlock.getMaxAddress().getOffset();
	}
	
	// Additional member variables
	private long[] theIncomingEdges;
	private long[] theOutgoingEdges;
	private boolean theHasCall;
	
	// Getters for the new fields
	public long[] getIncomingEdges() {
		return theIncomingEdges;
	}
	
	public long[] getOutgoingEdges() {
		return theOutgoingEdges;
	}
	
	public boolean hasCall() {
		return theHasCall;
	}
}
