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
		super();	
		
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
		
		// Start Address (aka Entry Point Address)
		theStartAddress = getStartAddressFromGhidra();
		
		// End Address
		theEndAddress  = getEndAddressFromGhidra();
		
		
		theInstructionContexts = getInstructionContextsFromGhidra();
		
		
		theIsInitialized = true;
		
		
		return theIsInitialized;
	}
	
	private InstructionContext [] getInstructionContextsFromGhidra()
	{
		
		ArrayList<InstructionContext>  instructionContextList=  new ArrayList<InstructionContext>();
		
		
		Address startAddress = theBasicBlock.getFirstStartAddress();	
		Instruction currentInstruction = theCurrentProgram.getListing().getInstructionAt(startAddress);		
		while(currentInstruction!=null && currentInstruction.getAddress().getOffset() <= theEndAddress)
		{
			
			GhidraInstructionContext ghidraInstructionContext = new GhidraInstructionContext(theCurrentProgram, currentInstruction);
			
			instructionContextList.add(ghidraInstructionContext);
			
			// Get the next instruction
			currentInstruction = currentInstruction.getNext();
		}
		
		InstructionContext [] instructionContexts = instructionContextList.toArray(new InstructionContext[instructionContextList.size()]);

		
		return instructionContexts;
	}
	
	private long getStartAddressFromGhidra()
	{
		
		long startAddress = theBasicBlock.getFirstStartAddress().getOffset();
				
		return startAddress;
	}
	
	private long getEndAddressFromGhidra()
	{

		long endAddress = theBasicBlock.getAddresses(false).next().getOffset();
		
		return endAddress;
	}
	
	

}
