package blackfyre.datatypes.ghidra;

import java.util.ArrayList;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.*;


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
	
	public boolean initialize()
	{
		if(theIsInitialized)
		{
			return theIsInitialized;
		}
		
		theStartAddress = getStartAddressFromGhidra();
		theEndAddress = getEndAddressFromGhidra();
		theInstructionContexts = getInstructionContextsFromGhidra();
		
		theIsInitialized = true;
		
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
					GhidraInstructionContext instructionContext = new GhidraInstructionContext(theCurrentProgram, instruction);
					instructionContexts.add(instructionContext);
				}
			}
		} catch (Exception e) {
			System.err.println("Error getting instruction contexts: " + e.getMessage());
			e.printStackTrace();
		}
		
		return instructionContexts.toArray(new InstructionContext[instructionContexts.size()]);
	}
	
	private long getStartAddressFromGhidra()
	{
		return theBasicBlock.getFirstStartAddress().getOffset();
	}
	
	private long getEndAddressFromGhidra()
	{
		return theBasicBlock.getMaxAddress().getOffset();
	}
}
