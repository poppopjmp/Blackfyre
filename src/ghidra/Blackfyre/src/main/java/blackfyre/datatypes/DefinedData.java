package blackfyre.datatypes;

import java.util.ArrayList;

import com.google.protobuf.ByteString;

import blackfyre.protobuf.BinaryContextOuterClass;

public class DefinedData {
	
	
	private long theAddress;
	private byte[] theData;
	private DataType theDataType;
	private ArrayList<Long> theReferences;
	private int theLength;
	
	
	
	public DefinedData(long address ,byte[] data, DataType dataType,ArrayList<Long>  references , int length)
	{
		setTheAddress(address);
		setTheData(data);		
		setTheDataType(dataType);
		setTheReferences(references);
		setTheLength(length);
	}


	public byte[] getTheData() {
		return theData;
	}


	public void setTheData(byte[] theData) {
		this.theData = theData;
	}


	public int getTheLength() {
		return theLength;
	}


	public void setTheLength(int theLength) {
		this.theLength = theLength;
	}


	public DataType getTheDataType() {
		return theDataType;
	}


	public void setTheDataType(DataType theDataType) {
		this.theDataType = theDataType;
	}


	public ArrayList<Long> getTheReferences() {
		return theReferences;
	}


	public void setTheReferences(ArrayList<Long> theReferences) {
		this.theReferences = theReferences;
	}
	
	public BinaryContextOuterClass.DefinedData toPB() 
	{
	
		var definedDataBuilder = BinaryContextOuterClass.DefinedData.newBuilder();
		
		definedDataBuilder.setAddress(theAddress);
		definedDataBuilder.setDataBytes(ByteString.copyFrom(theData));
		definedDataBuilder.setDataType(theDataType.getNumVal());
		definedDataBuilder.setLength(theLength);
		
		for (var reference : theReferences)
		{
			definedDataBuilder.addReferences(reference);
		}
		
		
		
		return definedDataBuilder.build();		
	}


	public long getTheAddress() {
		return theAddress;
	}


	public void setTheAddress(long theAddress) {
		this.theAddress = theAddress;
	}

}
