package blackfyre.datatypes;

import java.nio.ByteBuffer;

import blackfyre.protobuf.FunctionContextOuterClass;
import ghidra.util.datastruct.ByteArray;



public class FunctionContext {
	
	protected boolean theIsInitialized = false;
	
	protected String theFunctionName;
	
	protected long theStartAddress;
	
	protected long theEndAddress;
	
	protected String theSegmentName;
	
	protected boolean theIsThunk;
	
	protected int theTotalInstructions;
	
	protected BasicBlockContext [] theBasicBlockContexts;
	
	protected ProcessorType theProcType; // processor type (e.g. x86 vs ARM)
	
	protected String theDecompiledCode;
	
	public FunctionContext()
	{
		
		
	}
		
	
	public String getThefunctionName() {
		return theFunctionName;
	}


	public void setThefunctionName(String thefunctionName) {
		this.theFunctionName = thefunctionName;
	}


	public long getTheStartAddress() {
		return theStartAddress;
	}


	public void setTheStartAddress(long theStartAddress) {
		this.theStartAddress = theStartAddress;
	}


	public long getTheEndAddress() {
		return theEndAddress;
	}


	public void setTheEndAddress(long theEndAddress) {
		this.theEndAddress = theEndAddress;
	}


	public String getTheSegmentName() {
		return theSegmentName;
	}
	
	public int getTheTotalInstructions() {
		return theTotalInstructions;
	}
	public void setTheTotalInstructions(int theTotalInstructions) {
		this.theTotalInstructions = theTotalInstructions;
	}


	public void setTheSegmentName(String theSegmentName) {
		this.theSegmentName = theSegmentName;
	}
	
	public String getTheDecompiledCode() {
		return this.theDecompiledCode;
	}
	
	public boolean initialize()
	{
		/*Note: This is where the members of the class will need to be appropriately initialized
		 *      This should occur via the child class
		 */
		
		return false;
	}
	
	public void deinitialize()
	{
		
		// Deinitialize attributes that consume significant memory
		
		theBasicBlockContexts = null;
		theDecompiledCode = null;
		
		theIsInitialized = false;
		
		
	}
	
	
	public FunctionContextOuterClass.FunctionContext toPB() throws Exception
	{		
		var functionContextBuilder = FunctionContextOuterClass.FunctionContext.newBuilder();
		
		if(!initialize())
		{
			// Had an issue initializing, so we will return a uninitialized protobuf message
			
			return functionContextBuilder.build();
		}
		
		
		
		functionContextBuilder.setName(theFunctionName);
		
		functionContextBuilder.setStartAddress(theStartAddress);
		
		functionContextBuilder.setEndAddress(theEndAddress);
		
		functionContextBuilder.setProcType(theProcType.getNumVal());
		
		functionContextBuilder.setTotalInstructions(theTotalInstructions);
				
		
		functionContextBuilder.setIsThunk(theIsThunk);
		
		functionContextBuilder.setSegmentName(theSegmentName);
		
		functionContextBuilder.setDecompiledCode(theDecompiledCode);
		
		for( BasicBlockContext basicBlockContext : theBasicBlockContexts)
		{
			//Get the function protobuff object
			var  basicBlockContextPB = basicBlockContext.toPB();
			
			// Add the function protobuff object to the list
			functionContextBuilder.addBasicBlockContextList(basicBlockContextPB);
						
		}
		
		return functionContextBuilder.build();		
	}
	
	public byte[] toBytes() throws Exception         
    {
		
		/* Note: Create a TLV format for serializing the protobuf messages: 
         *       Type (1  byte); Length (4 bytes); Value (message bytes)
         *       
         */
		
		byte [] functionContextPBBytes = toPB().toByteArray();
		
		ByteBuffer byteBuffer = ByteBuffer.allocate(1+4+functionContextPBBytes.length);	
		
		// ** Type **
		byteBuffer.put((byte)MessageType.FUNCTION_CONTEXT_MSG.getNumVal());
		
		// ** Length **
		byteBuffer.putInt(functionContextPBBytes.length);
		
		// ** Value **
		byteBuffer.put(functionContextPBBytes);
		
		byte [] functionContextMessageBytes = byteBuffer.array();
		
		return functionContextMessageBytes;
		
    }
	
	
	


	
	
	
	

}
