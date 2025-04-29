package blackfyre.datatypes;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.function.Consumer;

import org.python.antlr.PythonParser.varargslist_return;

import blackfyre.protobuf.BinaryContextOuterClass;
import ghidra.program.model.listing.FunctionManager;

public class BinaryContext {

	final String BCC_VERSION = "1.0.1";

    final int MAX_BINARY_NAME_LENGTH = 100;

    final String BINARY_CONTEXT_CONTAINER_EXT = "bcc";

    protected String theName; // binary's name

    protected String theSHA256Hash; // binary's sha hash

    protected ProcessorType theProcType; // processor type (e.g. x86 vs ARM)

    protected FileType theFileType; // File type (e.g. ELF vs PE)

    protected WordSize theWordSize; // word size (e.g. 32-bit vs 64-bit)

    protected Endness theEndness; // endness (e.g. Big endian vs little endian)


    protected HashMap<Long, String> theStringRefs; // Key ==> address of where string referenced; value => string

    protected HashMap<Long, DefinedData> theDefinedDataMap; // key==> address of where data referenced; value => data

    protected ImportSymbol[] theImportSymbols;

    protected ExportSymbol[] theExportSymbols;

    protected FunctionContext [] theFunctionContexts;

    protected int theTotalFunctions ; // number of functions in the binary

    protected int theTotalInstructions; // number of the instructions in the entire binary

    protected String theLanguageID; //  Ghidra language id (e.g. "ARM:LE:64:v7")

    protected DisassemblerType theDisassemblerType;

    // The Caller map  key:value  key--> target function address; value --> list of the callers
    protected HashMap<Long,ArrayList<Long> > theCalleeToCallersMap;

 // The Callee map  key:value  key--> target function address; value --> list of the callees
    protected HashMap<Long,ArrayList<Long> > theCallerToCalleesMap;

    protected long theFileSize ;


    protected Path theRawBinaryFilePath; // File Path of the raw binary

    protected String theDisassemblerVersion; // Version of the Disassembler

    public BinaryContext()
    {

    }

    public boolean initialize() throws Exception
    {
        // This is intended to be overridden by subclasses like GhidraBinaryContext
        // Providing a base implementation that returns false
        System.out.println("Warning: Using base BinaryContext.initialize(), this method should be overridden by a subclass");
        return false;
    }




    /* Getters */

    public HashMap<Long, String> getStringRefs()
    {
        return theStringRefs;
    }

    public ImportSymbol[] getImportSymbols() {
        return theImportSymbols;
    }

    public ExportSymbol[] getExportSymbols() {

    	return theExportSymbols;
    }

    public int getTotalFunctions() {
        return theTotalFunctions;
    }

    public int getTotalInstructions() {
    	return theTotalInstructions;
    }


    public FunctionContext[] getFunctionContexts() {
        return theFunctionContexts;
    }


    public String getName() {

        return theName;
    }

    public String getSHA256Hash() {
        return theSHA256Hash;
    }

    public ProcessorType getProcType() {
        return theProcType;
    }

    public FileType getFileType() {
        return theFileType;
    }

    public WordSize getWordSize() {
        return theWordSize;
    }

    public Endness getEndness() {
        return theEndness;
    }

    public  HashMap<Long, DefinedData> getDefinedDataRefs()
    {
        return theDefinedDataMap;
    }

    public long getFileSize()
    {
        return theFileSize;
    }

    public String getDisassemblerVersion()
    {
        return theDisassemblerVersion;
    }


    protected void addImportSymbolstoBinaryContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {
     // ************************ Import Symbols ***********************************
        int numberImportSymbolsProccessed = 0;
        int totalImportSymbols  = theImportSymbols.length;
        for( ImportSymbol importSymbol : theImportSymbols)
        {
            //Get the function protobuf object
            var  importSymbolPB = importSymbol.toPB();

            // Add the function protobuf object to the list
            binaryContextBuilder.addImportSymbolList(importSymbolPB);

            numberImportSymbolsProccessed++;

            String progressMessage = String.format("[%d/%d] Processed Import Symbol: %s (0x%08X)  Library: %s",
                                                    numberImportSymbolsProccessed,
                                                   totalImportSymbols,
                                                   importSymbol.theImportName,
                                                   importSymbol.theAddress,
                                                   importSymbol.theLibraryName);
            System.out.println(progressMessage);
        }

    }

    protected void addExportSymbolstoBinaryContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {
     // ************************ Import Symbols ***********************************
        int numberExportSymbolsProccessed = 0;
        int totalImportSymbols  = theExportSymbols.length;
        for( ExportSymbol exportSymbol : theExportSymbols)
        {
            //Get the function protobuf object
            var  exportSymbolPB = exportSymbol.toPB();

            // Add the function protobuf object to the list
            binaryContextBuilder.addExportSymbolList(exportSymbolPB);

            numberExportSymbolsProccessed++;

            String progressMessage = String.format("[%d/%d] Processed Export Symbol: %s (0x%08X)  Library: %s",
                                                    numberExportSymbolsProccessed,
                                                   totalImportSymbols,
                                                   exportSymbol.theExportName,
                                                   exportSymbol.theAddress,
                                                   exportSymbol.theLibraryName);
            System.out.println(progressMessage);
        }

    }

    protected void setCallerToCalleesMapOfBinarContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {
    	int numberOfCallers = theCallerToCalleesMap.size();
    	int numberCallersProcessed = 0;

    	for( var callerToCalleesEntry : theCallerToCalleesMap.entrySet())
    	{
    		long callerAddress = callerToCalleesEntry.getKey();

    		ArrayList<Long> calleeList = callerToCalleesEntry.getValue();

    		var listOfCalleesBuilder = BinaryContextOuterClass.ListOfCallees.newBuilder();

    		for(var calleeAddress : calleeList)
    		{
    			listOfCalleesBuilder.addCallees(calleeAddress);
    		}

    		var listOfCalleesPB = listOfCalleesBuilder.build();

    		binaryContextBuilder.putCallerToCalleesMap(callerAddress, listOfCalleesPB);

    		String progressMessage = String.format("[%d/%d]  Processed Caller to Callees: [0x%08X]",
    				numberCallersProcessed,
    				numberOfCallers,
    				callerAddress);

            System.out.println(progressMessage);

            numberCallersProcessed++;

    	}

    }

    protected void setCalleeToCallersMapOfBinarContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {

    	int numberOfCallees = theCalleeToCallersMap.size();
    	int numberCalleesProcessed = 0;

    	for( var calleeToCallersEntry : theCalleeToCallersMap.entrySet())
    	{
    		long calleeAddress = calleeToCallersEntry.getKey();

    		ArrayList<Long> callerList = calleeToCallersEntry.getValue();

    		var listOfCallersBuilder = BinaryContextOuterClass.ListOfCallers.newBuilder();

    		for(var callerAddress : callerList)
    		{
    			listOfCallersBuilder.addCallers(callerAddress);
    		}

    		var listOfCallersPB = listOfCallersBuilder.build();

    		binaryContextBuilder.putCalleeToCallersMap(calleeAddress, listOfCallersPB);

    		String progressMessage = String.format("[%d/%d]  Processed Callee to Callers: [0x%08X]",
    				numberCalleesProcessed,
    				numberOfCallees,
    				calleeAddress);

            System.out.println(progressMessage);

            numberCalleesProcessed++;

    	}

    }

    protected void setStringRefofBinaryContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {

      //************************ String Refs ***********************************
        int totalStringRefs = theStringRefs.size();
        int numberStringRefsProcessed = 0;

        for(long address : theStringRefs.keySet())
        {
            String programString = theStringRefs.get(address);

            binaryContextBuilder.putStringRefs(address, programString);
            numberStringRefsProcessed++;

            String progressMessage = String.format("[%d/%d]  Processed String Reference: [0x%08X] '%s' ",
                    numberStringRefsProcessed,
                    totalStringRefs,
                    address,
                    programString);

            System.out.println(progressMessage);
        }

    }

    protected void setDefinedDataMapOfBinaryContextPB(BinaryContextOuterClass.BinaryContext.Builder binaryContextBuilder)
    {
    	for(long address: theDefinedDataMap.keySet())
    	{

    		DefinedData definedData = theDefinedDataMap.get(address);

    		var definedDataPB = definedData.toPB();

    		binaryContextBuilder.putDefinedDataMap(address, definedDataPB);

    	}
    }

    public  BinaryContextOuterClass.BinaryContext.Builder initializeBinaryContextBuilder() throws Exception
    {
    	initialize();

    	// Create the Builder
        var binaryContextBuilder = BinaryContextOuterClass.BinaryContext.newBuilder();

        // Binary Name
        binaryContextBuilder.setName(theName);

        //SHA-256 Hash
        binaryContextBuilder.setSha256Hash(theSHA256Hash);

        //Processor Type
        binaryContextBuilder.setProcType(theProcType.getNumVal());

        // File Type
        binaryContextBuilder.setFileType(theFileType.getNumVal());

        // Word Size
        binaryContextBuilder.setWordSize(theWordSize.getNumVal());

        // Endness
        binaryContextBuilder.setEndness(theEndness.getNumVal());

        // BCC  Version
        binaryContextBuilder.setBccVersion(BCC_VERSION);

        binaryContextBuilder.setTotalInstructions(theTotalInstructions);

        binaryContextBuilder.setFileSize(theFileSize);


        // Set the String Refs
        setStringRefofBinaryContextPB(binaryContextBuilder);

        // Add the import symbols
        addImportSymbolstoBinaryContextPB(binaryContextBuilder);

        // Set the total of functions in the binary
        binaryContextBuilder.setTotalFunctions(getTotalFunctions());

        // Set the Ghidra Language ID
        binaryContextBuilder.setLanguageId(theLanguageID);

        // Set the Disassembler Type
        binaryContextBuilder.setDisassemblerType(theDisassemblerType.getNumVal());

       // Set Disassembler Version
        binaryContextBuilder.setDisassemblerVersion(theDisassemblerVersion);


        // Set the Caller to Callees Map
        setCallerToCalleesMapOfBinarContextPB(binaryContextBuilder);

        // Set the Callee to Callers Map
        setCalleeToCallersMapOfBinarContextPB(binaryContextBuilder);

        // set the DefinedDataMap
        setDefinedDataMapOfBinaryContextPB(binaryContextBuilder);


        // Add the Export Symbols
        addExportSymbolstoBinaryContextPB(binaryContextBuilder);



        return binaryContextBuilder;

    }


    public BinaryContextOuterClass.BinaryContext toPB() throws Exception {

        /* Note: FunctionContexts are not added into the BinaryContext protobuf because of size limits
         *       protobuf (~65 MB).  Therefore the FunctionContexts will reside in their individual
         *       protobuf message.  During serialization to bytes (i.e. toBytes()), the function context will
         *       be concatenated to the end of the BinaryContext protobuf message serialized bytes.
        */
        var binaryContextBuilder = initializeBinaryContextBuilder();


        return binaryContextBuilder.build();

    }

    public byte[] toBytes() throws Exception
    {
      // Overload the message to default 'includeRawBinary' to be 'true'
    	return toBytes(true,true);
    }

    public byte[] toBytes(boolean includeRawBinary, boolean includeDecompiledCode) throws Exception
    {
        /* Note: Create a TLV format for serializing the protobuf messages:
         *       Type (1  byte); Length (4 bytes); Value (message bytes)
         *
         *       The bytes will consist of the following:
         *       1. BinaryContext PB Message  [TLV]
         *       2. First FunctionFunction Context PB Message [TLV]
         *       ......
         *       N-1. Last Function Context PB Message [TLV]
         *       N.  Sha-256 of 1 through N-1
         *
         *
         *       https://stackoverflow.com/questions/664389/byte-array-of-unknown-length-in-java
         *       https://stackoverflow.com/questions/22516923/bytearrayoutputstream-for-shorts-instead-of-bytes
         */


    	// Create the stream to hold the bytes of the messages of the BinaryContext and the FunctionContext
        ByteArrayOutputStream outputMessageStream =  new ByteArrayOutputStream();
        DataOutputStream  dataOutputMessageStream = new DataOutputStream(outputMessageStream);

        //************************ BinaryContext PB Message **************************
        byte [] binaryContextPBBytes =toPB().toByteArray();

        // Type
        dataOutputMessageStream.write((byte)MessageType.BINARY_CONTEXT_MSG.getNumVal());

        //Length
        dataOutputMessageStream.writeInt(binaryContextPBBytes.length);

        //Value
        dataOutputMessageStream.write(binaryContextPBBytes, 0 , binaryContextPBBytes.length);

        // ************ END  BinaryContext PB Message **********



        // ************ FunctionContext PB Messages ******************
        int numberFunctionsProcessed = 0;
        for(var functionContext : theFunctionContexts)
        {
        	var functionContextMessageBytes = functionContext.toBytes();

        	dataOutputMessageStream.write(functionContextMessageBytes,0, functionContextMessageBytes.length );


        	numberFunctionsProcessed++;
			String progressMessage = String.format("[%d/%d] Processed Function: %s (0x%08X)",
					                               numberFunctionsProcessed,
					                               theTotalFunctions,
					                               functionContext.getThefunctionName(),
					                               functionContext.getTheStartAddress());
			System.out.println(progressMessage);
        }


        byte [] message_bytes = outputMessageStream.toByteArray();
        // *****************END FunctionContext PB MESAGES ***************


        // **********************Raw Binary******************************


       // Type
        dataOutputMessageStream.write((byte)MessageType.RAW_BINARY_MSG.getNumVal());

        if(includeRawBinary)
        {
        	byte[] rawBinaryFileBytes = Files.readAllBytes(theRawBinaryFilePath);

            //Length
            dataOutputMessageStream.writeInt(rawBinaryFileBytes.length);

            //Value
            dataOutputMessageStream.write(rawBinaryFileBytes, 0 , rawBinaryFileBytes.length);

        }
        else
        {
        	//Since we are not including the raw binary, we will write the length to be 0

        	//Length
            dataOutputMessageStream.writeInt(0);
        }





        // ********************END Raw Binary****************************


        // **************** Compute the Sha256 of the message *********
        message_bytes = outputMessageStream.toByteArray();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] sha256_hash = digest.digest(message_bytes);


        // Append the sha-256 to the end of the message
        dataOutputMessageStream.write(sha256_hash,0, sha256_hash.length );


        message_bytes = outputMessageStream.toByteArray();
        //*********************END Compute Sha256**********************






        // *********************** Compress the message *****************
        Deflater deflater = new Deflater();
        deflater.setInput(message_bytes);
        deflater.finish();


        byte[] buff = new byte[1024];

        ByteArrayOutputStream outputStream =  new ByteArrayOutputStream(message_bytes.length);

        while(!deflater.finished())
        {
            int num_compressed_bytes = deflater.deflate(buff);
            outputStream.write(buff, 0, num_compressed_bytes);
        }

        outputStream.close();

        byte[] compressed_message = outputStream.toByteArray();

        System.out.println("Compressed message length:" + compressed_message.length);


        return compressed_message;
    }

    public  String saveToFile(String folderPath) throws Exception
    {
    	return saveToFile(folderPath,true, true);
    }

    public String saveToFile(String folderPath, boolean includeRawBinary, boolean includeDecompiledCode) throws Exception
    {
        initialize();



        String name =  theName;
        name = name.substring(0, Math.min(name.length(), MAX_BINARY_NAME_LENGTH));


        String sha256 = theSHA256Hash;

        String binaryContextFileName = String.format("%s_%s.%s",  name, sha256,BINARY_CONTEXT_CONTAINER_EXT);

        Path filePath = Paths.get(folderPath, binaryContextFileName);


        byte[] binaryContextBytes = toBytes(includeRawBinary, includeDecompiledCode);


        Files.write(filePath, binaryContextBytes);


        String message = String.format("(%.2f kb) Saved BinaryContext to the following directory:%s",
                                         (double)binaryContextBytes.length/1000,
                                         filePath.toString());

        return message;


    }

    public String toBytesAndWriteToFile(String outputPath, boolean includeRawBinary, boolean includeDecompiledCode, Consumer<String> logger) throws Exception {


    	 /* Note: Create a TLV format for serializing the protobuf messages:
         *       Type (1  byte); Length (4 bytes); Value (message bytes)
         *
         *       The bytes will consist of the following:
         *       1. BinaryContext PB Message  [TLV]
         *       2. First FunctionFunction Context PB Message [TLV]
         *       ......
         *       N-1. Last Function Context PB Message [TLV]
         *       N.  Sha-256 of 1 through N-1
         *
         *
         *       https://stackoverflow.com/questions/664389/byte-array-of-unknown-length-in-java
         *       https://stackoverflow.com/questions/22516923/bytearrayoutputstream-for-shorts-instead-of-bytes
         */
    	String name =  theName;
        name = name.substring(0, Math.min(name.length(), MAX_BINARY_NAME_LENGTH));




        String sha256 = theSHA256Hash;

        String binaryContextFileName = String.format("%s_%s.%s",  name, sha256,BINARY_CONTEXT_CONTAINER_EXT);



        // Create a temporary file
        Path tempFilePath = Files.createTempFile("temp_"+binaryContextFileName, ".tmp");
        System.out.println("Temporary file path: " + tempFilePath.toString());



    	int fileCounter = 0;
        // Initialize a FileOutputStream to write directly to a file
    	Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, false); // false ensures zlib headers are used

        try (FileOutputStream fileOutStream = new FileOutputStream(tempFilePath.toString());
             DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(fileOutStream, deflater); // For compression
             DataOutputStream dataOutputMessageStream = new DataOutputStream(deflaterOutputStream))
        {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");


            // =======================================Binary Context =========================================

            // Process BinaryContext PB Message
            byte[] binaryContextPBBytes = toPB().toByteArray();

            writeMessage(dataOutputMessageStream, MessageType.BINARY_CONTEXT_MSG, binaryContextPBBytes, digest);

            // ================================= END Binary Context =========================================


            // ====================================Function Context =========================================
            // Process each FunctionContext
            int numberFunctionsProcessed = 0;
            for (var functionContext : theFunctionContexts) {

            	// Note: toBytes() for functioncontext already formats the message as TLV
                var functionContextMessageBytes = functionContext.toBytes();
                writeMessage(dataOutputMessageStream, MessageType.FUNCTION_CONTEXT_MSG, functionContextMessageBytes, digest);



                numberFunctionsProcessed++;
    			String progressMessage = String.format("[%d/%d] Processed Function: %s (0x%08X)",
    					                               numberFunctionsProcessed,
    					                               theTotalFunctions,
    					                               functionContext.getThefunctionName(),
    					                               functionContext.getTheStartAddress());
    			logger.accept(progressMessage);
    			System.out.println(progressMessage);
    			
    			
				functionContext.deinitialize();	
            }
            // =================================END Function Context=========================================	

            
            // ======================================= Raw Binary ============================================	
            // Process Raw Binary
            if (includeRawBinary) {
                byte[] rawBinaryFileBytes = Files.readAllBytes(theRawBinaryFilePath);
                writeMessage(dataOutputMessageStream, MessageType.RAW_BINARY_MSG, rawBinaryFileBytes, digest);
            } else {
                writeMessage(dataOutputMessageStream, MessageType.RAW_BINARY_MSG, null, digest); // Write empty message for raw binary
            }
             // =======================================END  Raw Binary ============================================	

            
            
	     // ============================================ SHA Hash ==================================================	
			// Append SHA-256 hash to the file
			byte[] sha256Hash = digest.digest();
			dataOutputMessageStream.write(sha256Hash, 0, sha256Hash.length);
			dataOutputMessageStream.flush();
	     // ============================================  END SHA Hash ==================================================	
			    
			
			dataOutputMessageStream.flush();
			dataOutputMessageStream.close();
			    
			    
			 // After all processing is done, move the temporary file to the desired location
			Path finalFilePath = Paths.get(outputPath, binaryContextFileName);
			Files.move(tempFilePath, finalFilePath, StandardCopyOption.REPLACE_EXISTING);
			
			System.out.println("Data written to file: " + finalFilePath.toString());

            
			// Calculate the total size of the written data
			// And return a message indicating the size and location of the written data
			File outputFile = new File(finalFilePath.toString());
			double fileSizeBytes = outputFile.length();
			String sizeUnit;
			double fileSize;
			
			if (fileSizeBytes < 1024 * 1024) 
			{ 	
				// If file size is less than 1MB, display in KB
				fileSize = fileSizeBytes / 1024.0;
				sizeUnit = "KB";
			} 
			else 
			{ // Otherwise, display in MB
				fileSize = fileSizeBytes / (1024.0 * 1024.0);
				sizeUnit = "MB";
			}

			String logMessage = String.format("(%.2f %s) Saved data to the following directory: %s", fileSize, sizeUnit, outputPath);

  
			return logMessage;  
        }
    }

    
    private void writeMessage(DataOutputStream out, MessageType messageType, byte[] messageBytes, MessageDigest digest) throws IOException {
        
    	
    	
    	if(messageType == MessageType.BINARY_CONTEXT_MSG )
    	{
    		// Write the message type as a byte
            out.write((byte) messageType.getNumVal());
            digest.update((byte)messageType.getNumVal());
        	
        	
            // Write the length of the message as an integer
            out.writeInt(messageBytes.length);
            ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
            buffer.putInt(messageBytes.length);
            byte[] bufferBytes = buffer.array();
            digest.update(bufferBytes, 0, bufferBytes.length);
            
            // Write the actual message bytes
            out.write(messageBytes,0,messageBytes.length);
            
            out.flush();

            // Update the SHA-256 digest with the new message bytes
            digest.update(messageBytes,0, messageBytes.length);
    		
    		
    	}
    	else if (messageType == MessageType.RAW_BINARY_MSG)
    	{
    		
    		// Write the message type as a byte
            out.write((byte) messageType.getNumVal());
            digest.update((byte)messageType.getNumVal());
        	
            
            if( messageBytes == null)
            {
            	// Write the length of the message to be 0
                out.writeInt(0);
                ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
                buffer.putInt(0);
                byte[] bufferBytes = buffer.array();
                digest.update(bufferBytes, 0, bufferBytes.length);
            }
            else
            {
            	// Write the length of the message as an integer
                out.writeInt(messageBytes.length);
                ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
                buffer.putInt(messageBytes.length);
                byte[] bufferBytes = buffer.array();
                digest.update(bufferBytes, 0, bufferBytes.length);
                
                // Write the actual message bytes
                out.write(messageBytes,0,messageBytes.length);

                // Update the SHA-256 digest with the new message bytes
                digest.update(messageBytes,0, messageBytes.length);
        		
            }
    		
    		
    	}
    	
    	else if (messageType == MessageType.FUNCTION_CONTEXT_MSG)
    	{
    		
    		// Note: Function_Context is already formated as TLV when we call the toBytes() of functionContext
    		
    		// Write the actual message bytes
            out.write(messageBytes,0,messageBytes.length);

            // Update the SHA-256 digest with the new message bytes
            digest.update(messageBytes,0, messageBytes.length);
    		
    	}
    	
        
    }


    
    

}
