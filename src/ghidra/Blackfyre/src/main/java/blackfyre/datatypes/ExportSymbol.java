package blackfyre.datatypes;

import blackfyre.protobuf.BinaryContextOuterClass;

public class ExportSymbol {
	
	protected boolean theIsInitialized = false;

    // Import Symbol Name
    protected String theExportName;

    // Library
    protected String theLibraryName;

    // Address of symbol
    protected long theAddress;

    public ExportSymbol(String functionName, String libraryName, long address) {
        theExportName = functionName;

        theLibraryName = libraryName;

        theAddress = address;
    }

	public BinaryContextOuterClass.ExportSymbol toPB() 
	{
	
		var exportSymbolBuilder = BinaryContextOuterClass.ExportSymbol.newBuilder();
		

		exportSymbolBuilder.setAddress(theAddress);
		exportSymbolBuilder.setExportName(theExportName);
		exportSymbolBuilder.setLibraryName(theLibraryName);
		
		return exportSymbolBuilder.build();		
	}

}
