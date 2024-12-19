package blackfyre.datatypes;
import blackfyre.protobuf.BinaryContextOuterClass;

public class ImportSymbol {

    protected boolean theIsInitialized = false;

    // Import Symbol Name
    protected String theImportName;

    // Library
    protected String theLibraryName;

    // Address of symbol
    protected long theAddress;

    public ImportSymbol(String functionName, String libraryName, long address) {
        theImportName = functionName;

        theLibraryName = libraryName;

        theAddress = address;
    }

	public BinaryContextOuterClass.ImportSymbol toPB() 
	{
	
		var importSymbolBuilder = BinaryContextOuterClass.ImportSymbol.newBuilder();
		

		importSymbolBuilder.setAddress(theAddress);
		importSymbolBuilder.setImportName(theImportName);
		importSymbolBuilder.setLibraryName(theLibraryName);
		
		return importSymbolBuilder.build();		
	}

}
