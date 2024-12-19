package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import blackfyre.datatypes.InstructionContext;

public class GhidraInstructionContext extends InstructionContext {
	
	private Program theCurrentProgram;
	
	private Instruction theInstruction;
	
	public GhidraInstructionContext(Program currentProgram, Instruction instruction)
	{
		theCurrentProgram = currentProgram;
		
		theInstruction  = instruction;
	}
	
	public boolean initialize()
	{
		
		if(theIsInitialized)
		{
			return theIsInitialized;
		}
		
		theAddress  =  getAddressFromGhidra();
		
		try 
		{
			theOpcodeBytes  = getOpcodeBytesFromGhidra();
		} 
		catch (MemoryAccessException e)
		{
			e.printStackTrace();
			System.err.println("Unable to get instruction bytes at "+theAddress);
			return false;
		}
		
		theMnemonic  = getMnemonicFromGhidra();

		
		
		theIsInitialized = true;
		
		
		return theIsInitialized;
	}
	
	private long getAddressFromGhidra()
	{
		
		return theInstruction.getAddress().getOffset();
	}
	
	private byte [] getOpcodeBytesFromGhidra() throws MemoryAccessException
	{
		return theInstruction.getBytes();
	}
	
	private String getMnemonicFromGhidra()
	{
		return theInstruction.getMnemonicString().toLowerCase();
	}

}
