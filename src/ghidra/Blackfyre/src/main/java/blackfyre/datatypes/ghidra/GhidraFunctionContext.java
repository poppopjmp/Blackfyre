package blackfyre.datatypes.ghidra;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

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
	
	/**
	 * Collects caller and callee relationships for the function
	 * @return Array of addresses that call this function
	 */
	private long[] getCallerAddressesFromGhidra() {
		ArrayList<Long> callerAddresses = new ArrayList<>();
		
		// Get references to this function
		var references = theCurrentProgram.getReferenceManager().getReferencesTo(theFunction.getEntryPoint());
		
		for (var reference : references) {
			if (reference.getReferenceType().isCall()) {
				callerAddresses.add(reference.getFromAddress().getOffset());
			}
		}
		
		// Convert to primitive long array
		long[] result = new long[callerAddresses.size()];
		for (int i = 0; i < callerAddresses.size(); i++) {
			result[i] = callerAddresses.get(i);
		}
		
		return result;
	}
	
	/**
	 * Collects addresses of functions called by this function
	 * @return Array of addresses called by this function
	 */
	private long[] getCalleeAddressesFromGhidra() {
		ArrayList<Long> calleeAddresses = new ArrayList<>();
		
		// Get all instructions in the function
		var listing = theCurrentProgram.getListing();
		
		for (Instruction instruction : listing.getInstructions(theFunction.getBody(), true)) {
			// Check if this instruction is a call
			var flowType = instruction.getFlowType();
			if (flowType.isCall()) {
				// Get the called address
				var flows = instruction.getFlows();
				for (var flow : flows) {
					var targetFunction = theCurrentProgram.getFunctionManager().getFunctionAt(flow);
					if (targetFunction != null) {
						calleeAddresses.add(targetFunction.getEntryPoint().getOffset());
					}
				}
			}
		}
		
		// Convert to primitive long array
		long[] result = new long[calleeAddresses.size()];
		for (int i = 0; i < calleeAddresses.size(); i++) {
			result[i] = calleeAddresses.get(i);
		}
		
		return result;
	}
	
	/**
	 * Gets the calling convention of the function
	 * @return String representation of the calling convention
	 */
	private String getCallingConventionFromGhidra() {
		var convention = theFunction.getCallingConventionName();
		return convention != null ? convention : "unknown";
	}
	
	/**
	 * Gets the stack frame size of the function
	 * @return Size of the stack frame
	 */
	private int getStackFrameSizeFromGhidra() {
		return theFunction.getStackFrame() != null ? theFunction.getStackFrame().getLocalSize() : 0;
	}
	
	/**
	 * Determines if the function is a library function
	 * @return True if the function is from a library
	 */
	private boolean getIsLibraryFromGhidra() {
		return theFunction.isExternal();
	}
	
	/**
	 * Analyzes if the function contains loops
	 * @return True if the function has loops
	 */
	private boolean getHasLoopsFromGhidra() throws CancelledException {
		SimpleBlockModel simpleBlockModel = new SimpleBlockModel(theCurrentProgram, false);
		AddressSetView addrset = theFunction.getBody();
		CodeBlockIterator iter = simpleBlockModel.getCodeBlocksContaining(addrset, theMonitor);
		
		// Build a graph of blocks to detect loops
		HashSet<Long> blockStarts = new HashSet<>();
		HashMap<Long, List<Long>> blockEdges = new HashMap<>();
		
		while (iter.hasNext()) {
			CodeBlock block = iter.next();
			long blockStart = block.getFirstStartAddress().getOffset();
			blockStarts.add(blockStart);
			
			// Get destinations
			ArrayList<Long> destinations = new ArrayList<>();
			var destIter = block.getDestinations(theMonitor);
			while (destIter.hasNext()) {
				var dest = destIter.next();
				destinations.add(dest.getDestinationAddress().getOffset());
			}
			blockEdges.put(blockStart, destinations);
		}
		
		// Check for loops using basic cycle detection
		for (Long start : blockStarts) {
			HashSet<Long> visited = new HashSet<>();
			if (hasLoop(start, blockEdges, visited, new HashSet<>())) {
				return true;
			}
		}
		
		return false;
	}
	
	private boolean hasLoop(Long current, HashMap<Long, List<Long>> edges, HashSet<Long> visited, HashSet<Long> recursionStack) {
		// If already in recursion stack, we found a loop
		if (recursionStack.contains(current)) {
			return true;
		}
		
		// If already visited but not in recursion stack, no loop in this path
		if (visited.contains(current)) {
			return false;
		}
		
		// Add to both visited and recursion stack
		visited.add(current);
		recursionStack.add(current);
		
		// Check all destinations
		List<Long> destinations = edges.get(current);
		if (destinations != null) {
			for (Long dest : destinations) {
				if (hasLoop(dest, edges, visited, recursionStack)) {
					return true;
				}
			}
		}
		
		// Remove from recursion stack
		recursionStack.remove(current);
		return false;
	}
	
	/**
	 * Gets cross references to this function
	 * @return Map of cross references with address and type
	 */
	private HashMap<Long, String> getXrefsFromGhidra() {
		HashMap<Long, String> xrefs = new HashMap<>();
		
		var references = theCurrentProgram.getReferenceManager().getReferencesTo(theFunction.getEntryPoint());
		
		for (var reference : references) {
			String type = reference.getReferenceType().toString();
			xrefs.put(reference.getFromAddress().getOffset(), type);
		}
		
		return xrefs;
	}
	
	/**
	 * Gets architecture-specific information
	 * @return Architecture info as a map
	 */
	private HashMap<String, Object> getArchSpecificInfoFromGhidra() {
		HashMap<String, Object> archInfo = new HashMap<>();
		
		String processor = theCurrentProgram.getLanguage().getProcessor().toString().toLowerCase();
		archInfo.put("instruction_set", processor);
		
		ArrayList<String> extensions = new ArrayList<>();
		
		// Check processor specific extensions
		if (processor.contains("x86")) {
			// Check for x86 extensions in language description
			String desc = theCurrentProgram.getLanguage().getDescription().toLowerCase();
			if (desc.contains("sse")) {
				extensions.add("SSE");
			}
			if (desc.contains("avx")) {
				extensions.add("AVX");
			}
		} else if (processor.contains("arm")) {
			if (theCurrentProgram.getLanguage().getLanguageDescription().getSize() == 64) {
				extensions.add("AArch64");
			} else {
				// Check for ARM Thumb instructions
				if (theCurrentProgram.getLanguage().getLanguageID().getIdAsString().contains("thumb")) {
					extensions.add("Thumb");
				}
			}
		}
		
		archInfo.put("extensions", extensions.toArray(new String[0]));
		
		return archInfo;
	}

	@Override
	public boolean initialize() {
		
		if(theIsInitialized) {
			return theIsInitialized;
		}
		
		try {
			// Existing fields
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
			theBasicBlockContexts = getBasicBlockContextsFromGhidra();
			
			// Additional fields to match other plugins
			theCallerAddresses = getCallerAddressesFromGhidra();
			theCalleeAddresses = getCalleeAddressesFromGhidra();
			theCallingConvention = getCallingConventionFromGhidra();
			theStackFrameSize = getStackFrameSizeFromGhidra();
			theIsLibrary = getIsLibraryFromGhidra();
			
			try {
				theHasLoops = getHasLoopsFromGhidra();
			} catch (CancelledException e) {
				theHasLoops = false;
			}
			
			theXrefs = getXrefsFromGhidra();
			theArchInfo = getArchSpecificInfoFromGhidra();
			
			theIsInitialized = true;
		} catch (Exception e) {
			System.err.println("Failed initializing function context for: " + theFunctionName);
			e.printStackTrace();
			return false;
		}
		
		return theIsInitialized;
	}
	
	// Additional member variables to store the new data
	private long[] theCallerAddresses;
	private long[] theCalleeAddresses;
	private String theCallingConvention;
	private int theStackFrameSize;
	private boolean theIsLibrary;
	private boolean theHasLoops;
	private HashMap<Long, String> theXrefs;
	private HashMap<String, Object> theArchInfo;
	
	// Getters for the new fields
	public long[] getCallerAddresses() {
		return theCallerAddresses;
	}
	
	public long[] getCalleeAddresses() {
		return theCalleeAddresses;
	}
	
	public String getCallingConvention() {
		return theCallingConvention;
	}
	
	public int getStackFrameSize() {
		return theStackFrameSize;
	}
	
	public boolean isLibrary() {
		return theIsLibrary;
	}
	
	public boolean hasLoops() {
		return theHasLoops;
	}
	
	public HashMap<Long, String> getXrefs() {
		return theXrefs;
	}
	
	public HashMap<String, Object> getArchInfo() {
		return theArchInfo;
	}
}
