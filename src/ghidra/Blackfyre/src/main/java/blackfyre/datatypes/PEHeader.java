package blackfyre.datatypes;


import blackfyre.protobuf.PEHeaderOuterClass;

public class PEHeader  {

    protected int theTimeStamp;
    protected long theSizeOfImage;
    protected long theAddressOfEntryPoint;    
    protected long theSizeOfInitializedData ;
    
    protected long theSizeOfCode ;
    protected int  theSizeOfRawData ;
    protected int theChecksum ;
    protected int theDllCharacteristics ;
    
    protected int theNumberOfSections;        
    protected int theMajorLinkerVersion ;
    protected int theMajorImageVersion ;
    protected long theSizeOfUnitializedData;
    
    protected long theBaseOfCode;     
    protected int theMinorLinkerVersion;        
    protected int theSizeOfHeaders ;
    protected int theMajorOperatingSystemVersion ;
    
    protected long theSizeOfStackReserve ;
    protected int theFileAlignment ;
    protected int theMinorImageVersion ;
    protected int theMajorSubsystemVersion ;
    
    protected long theSizeofStackCommit ;
    protected long theSizeOfHeapReserve ;       
    protected String theNtHeaderName ;
    

    public PEHeader(int timeStamp, long sizeOfImage, long addressOfEntryPoint, long sizeOfInitializedData,
    		long sizeOfCode,int  sizeOfRawData ,int checksum , int dllCharacteristics, int numberOfSections,
    		int majorLinkerVersion ,int majorImageVersion,long sizeOfUnitializedData, long baseOfCode ,
    		int minorLinkerVersion,int sizeOfHeaders,int majorOperatingSystemVersion, long sizeOfStackReserve,
    		int fileAlignment ,int minorImageVersion, int majorSubsystemVersion ,long sizeofStackCommit ,
    		long sizeOfHeapReserve ,String ntHeaderName ) 
    {
    	theTimeStamp = timeStamp;    	
    	theSizeOfImage = sizeOfImage;    	
    	theAddressOfEntryPoint = addressOfEntryPoint;    	
    	theSizeOfInitializedData = sizeOfInitializedData;
        
        theSizeOfCode = sizeOfCode;
        theSizeOfRawData = sizeOfRawData;
        theChecksum = checksum;
        theDllCharacteristics = dllCharacteristics;
        
        theNumberOfSections = numberOfSections;        
        theMajorLinkerVersion = majorLinkerVersion;
        theMajorImageVersion = majorImageVersion;
        theSizeOfUnitializedData = sizeOfUnitializedData;
        
        theBaseOfCode = baseOfCode;     
        theMinorLinkerVersion = minorLinkerVersion;        
        theSizeOfHeaders = sizeOfHeaders;
        theMajorOperatingSystemVersion = majorOperatingSystemVersion;
        
        theSizeOfStackReserve = sizeOfStackReserve;
        theFileAlignment = fileAlignment ;
        theMinorImageVersion = minorImageVersion;
        theMajorSubsystemVersion = majorSubsystemVersion;
        
        theSizeofStackCommit = sizeofStackCommit ;
        theSizeOfHeapReserve = sizeOfHeapReserve;       
        theNtHeaderName = ntHeaderName;
    }
    
    
    /* Getters */

    public int getTimeStamp() {

        return theTimeStamp;
    }

    public long getSizeOfImage() {
        return theSizeOfImage;
    }

    public long getAddressOfEntryPoint() {
        return theAddressOfEntryPoint;
    }
    
    public PEHeaderOuterClass.PEHeader toPB() throws Exception
    {
    	
    	var peHeaderBuilder  = PEHeaderOuterClass.PEHeader.newBuilder();
    	
    	
    	peHeaderBuilder.setTimeStamp(theTimeStamp);   
    	peHeaderBuilder.setSizeOfImage(theSizeOfImage);
    	peHeaderBuilder.setAddressOfEntryPoint(theAddressOfEntryPoint);    	
    	peHeaderBuilder.setSizeOfInitializedData(theSizeOfInitializedData);    	
    	
    	peHeaderBuilder.setSizeOfCode(theSizeOfCode);    	
    	peHeaderBuilder.setSizeOfRawData(theSizeOfRawData);    	
    	peHeaderBuilder.setChecksum(theChecksum);    	
    	peHeaderBuilder.setDllCharacteristics(theDllCharacteristics);    	
    	
    	peHeaderBuilder.setNumberOfSections(theNumberOfSections);    	
    	peHeaderBuilder.setMajorLinkerVersion(theMajorLinkerVersion);    	
    	peHeaderBuilder.setMajorImageVersion(theMajorImageVersion);    	
    	peHeaderBuilder.setSizeOfUninitializedData(theSizeOfUnitializedData);    	
    	
    	peHeaderBuilder.setBaseOfCode(theBaseOfCode);    	
    	peHeaderBuilder.setMinorLinkerVersion(theMinorLinkerVersion);    	
    	peHeaderBuilder.setSizeOfHeaders(theSizeOfHeaders);    	
    	peHeaderBuilder.setMajorOperatingSystemVersion(theMajorOperatingSystemVersion);    	
    	
    	peHeaderBuilder.setSizeOfStackReserve(theSizeOfStackReserve);    	
    	peHeaderBuilder.setFileAlignment(theFileAlignment);    	
    	peHeaderBuilder.setMinorImageVersion(theMinorImageVersion);    	
    	peHeaderBuilder.setMajorSubsystemVersion(theMajorSubsystemVersion);    	
    	
    	peHeaderBuilder.setSizeOfStackCommit(theSizeofStackCommit);    	
    	peHeaderBuilder.setSizeOfHeapReserve(theSizeOfHeapReserve);    	
    	peHeaderBuilder.setNtHeaderName(theNtHeaderName);
    	
    	return peHeaderBuilder.build();
    	
    }
    
 
}
