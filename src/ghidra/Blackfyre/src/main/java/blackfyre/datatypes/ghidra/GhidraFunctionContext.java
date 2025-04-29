package blackfyre.datatypes.ghidra;

import java.util.ArrayList;

import blackfyre.datatypes.BasicBlockContext;
import blackfyre.datatypes.FunctionContext;
import blackfyre.datatypes.ProcessorType;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.program.flatapi.FlatProgramAPI;

public class GhidraFunctionContext extends FunctionContext{
	
	private Program theCurrentProgram;
	
	private Function theFunction;
	
	private TaskMonitor theMonitor;
	
	private boolean theIncludeDecompiledCode ;
	
	private int theDecompileTimeoutSeconds;
	
	public GhidraFunctionContext(Program currentProgram, 
			                     Function function,
			                     TaskMonitor monitor,
			                     ProcessorType procType,
			                     boolean includeDecompiledCode,
			                     int decompileTimeoutSeconds)
	{
		super();	
		
		theCurrentProgram = currentProgram;
		theFunction = function;
		theMonitor = monitor;
		theProcType = procType;
		theIncludeDecompiledCode = includeDecompiledCode;
		theDecompileTimeoutSeconds = decompileTimeoutSeconds;
	
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
		
		// Function Name
		theFunctionName  = getFunctionNameFromGhidra();
		
		// Segment Name (e.g. text, data, etc..)
		theSegmentName = getFunctionSegmentNameFromGhidra();
		
		// Is thunk
		theIsThunk  = getIsThunkFromGhidra();
		
		// Total Instructions
		theTotalInstructions = getTotalInstructionsFromGhidra();
		
		// Decompiled Code
		theDecompiledCode = getDecompliedCodeFromGhidra();
		
		
		// Basic Blocks
		try 
		{
			theBasicBlockContexts = getBasicBlockContextsFromGhidra();
		} 
		catch (CancelledException e) 
		{
			// TODO Auto-generated catch block
			System.err.println("Failed generating basic blocks for function: "+theFunctionName);
			return false;
		} 

			
		theIsInitialized = true;
				
		return theIsInitialized;
			
	}
	
	private String getDecompliedCodeFromGhidra()
	{
		
		String decompiledCode = "";
		
		// Only include the decompiled code if the flag is set to true
		if(theIncludeDecompiledCode)
		{
			var flatProgramAPI =  new FlatProgramAPI(theCurrentProgram);
			var flatDecompilerAPI =  new FlatDecompilerAPI(flatProgramAPI);
			
			try 
			{
				if(theDecompileTimeoutSeconds == 0)
				{
					// 0 ==> implies not timeout
					decompiledCode = flatDecompilerAPI.decompile(theFunction);
				}
				else
				{
					decompiledCode = flatDecompilerAPI.decompile(theFunction, theDecompileTimeoutSeconds);
				}
				
				
				flatDecompilerAPI.dispose(); // need to call after done; if not memory leak occurs
			} catch (Exception e) {
				// Do nothing... Unable to get the decompiled code
				String message = String.format("Unable to get decompiled code for function (%s):%s", getFunctionNameFromGhidra(), e);
				System.out.println(message);
			}	
		}
		
		return decompiledCode;
	}
	
	private BasicBlockContext [] getBasicBlockContextsFromGhidra() throws CancelledException
	{
		
		ArrayList<BasicBlockContext>  basicBlockListContext =  new ArrayList<BasicBlockContext>();
		
		SimpleBlockModel simpleBlockModel = new SimpleBlockModel(theCurrentProgram, false);
		
	    
    	AddressSetView addrset = theFunction.getBody();
    	
    	CodeBlockIterator simpleCBIter;

		simpleCBIter = simpleBlockModel.getCodeBlocksContaining(addrset, theMonitor);
		
		while (simpleCBIter.hasNext())
    	{
    		CodeBlock block = simpleCBIter.next();
    		
    		GhidraBasicBlockContext ghidraBasicBlockContext = new GhidraBasicBlockContext(theCurrentProgram, block, theProcType);
			
    		basicBlockListContext.add(ghidraBasicBlockContext);
    		    		
    	}
	

		GhidraBasicBlockContext [] disassemblyBasicBlocks = basicBlockListContext.toArray(new GhidraBasicBlockContext[basicBlockListContext.size()]);
					
		
		return disassemblyBasicBlocks;
	}
	
	
	private long getStartAddressFromGhidra()
	{
		
		long startAddress = theFunction.getEntryPoint().getOffset();
				
		return startAddress;
	}
	
	private long getEndAddressFromGhidra()
	{
		// Get the address sets for the function
		AddressSetView addressSet = theFunction.getBody();
		
		// Get the max address of function, where we will call it the end address
		long endAddress = addressSet.getMaxAddress().getOffset();
		
		return endAddress;
	}
	
	private int getTotalInstructionsFromGhidra()
	{
		int totalInstructions = 0;
		
				
		var listing = theCurrentProgram.getListing();
		
		for( @SuppressWarnings("unused") Instruction instruction : listing.getInstructions(theFunction.getBody(),true))
    	{
    		totalInstructions +=1;
    	}
    	    		
		
		return totalInstructions;
	}
	
	private String getFunctionNameFromGhidra()
	{
		
		return theFunction.getName();
	}
	
	private String getFunctionSegmentNameFromGhidra()
	{
		
		MemoryBlock memoryBlock = theCurrentProgram.getMemory().getBlock(theFunction.getEntryPoint());
		
		String segmentName = memoryBlock.getName();
		
		return segmentName;
	}
	
	private boolean getIsThunkFromGhidra()
	{
		
		return theFunction.isThunk();
	}


}
