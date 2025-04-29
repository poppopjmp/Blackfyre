package blackfyre.datatypes;

import blackfyre.protobuf.FunctionContextOuterClass;


public class BasicBlockContext {
	
	protected boolean theIsInitialized = false;
	
	protected long theStartAddress;
	
	protected long theEndAddress;
	
	protected InstructionContext [] theInstructionContexts;
	
	protected ProcessorType theProcType; // processor type (e.g. x86 vs ARM)
	
	public BasicBlockContext()
	{
		
	}
	
	public boolean initialize()
	{
		/*Note: This is where the members of the class will need to be appropriately initialized
		 *      This should occur via the child class
		 */
		
		return false;
	}
	
	public FunctionContextOuterClass.BasicBlockContext toPB() throws Exception
	{
	    var basicBlockContext = FunctionContextOuterClass.BasicBlockContext.newBuilder();
		
		if(!initialize())
		{
			// Had an issue initializing, so we will return a uninitialized protobuf message
			
			return basicBlockContext.build();
		}
		
	
		basicBlockContext.setStartAddress(theStartAddress);
		
		basicBlockContext.setEndAddress(theEndAddress);
		
		basicBlockContext.setProcType(theProcType.getNumVal());
		
		for( InstructionContext instructionContext : theInstructionContexts)
		{
			//Get the function protobuff object
			var  instructionContextPB = instructionContext.toPB();
			
			// Add the function protobuff object to the list
			basicBlockContext.addInstructionContextList(instructionContextPB);
						
		}
				

		
		return basicBlockContext.build();
		
	}

}
