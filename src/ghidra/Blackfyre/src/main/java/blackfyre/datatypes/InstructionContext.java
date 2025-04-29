package blackfyre.datatypes;


import com.google.protobuf.ByteString;
import blackfyre.protobuf.FunctionContextOuterClass;

public class InstructionContext {
	
	protected boolean theIsInitialized = false;	
	protected long theAddress;
	protected byte []  theOpcodeBytes;
	protected long theSize;
	protected String theMnemonic;
		
	public InstructionContext()
	{
		
	}
	
	public boolean initialize()
	{
		/*Note: This is where the members of the class will need to be appropriately initialized
		 *      This should occur via the child class
		 */
		
		return false;
	}
	
	public FunctionContextOuterClass.InstructionContext toPB() throws Exception
	{
	
		var instuctionContext = FunctionContextOuterClass.InstructionContext.newBuilder();
		
		if(!initialize())
		{
			// Had an issue initializing, so we will return a uninitialized protobuf message
			
			return instuctionContext.build();
		}

		
		instuctionContext.setAddress(theAddress);
		instuctionContext.setMnemonic(theMnemonic);
		instuctionContext.setOpcodeBytes(ByteString.copyFrom(theOpcodeBytes));
		
		
		return instuctionContext.build();
		
	}
	
	
	

}
