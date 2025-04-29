package blackfyre.datatypes;

import blackfyre.protobuf.ELFHeaderOuterClass;

public class ELFHeader {
    private int elfClass; // 32-bit (1) or 64-bit (2)
    private int dataEncoding; // Little endian (1) or big endian (2)
    private int fileVersion; // Should be 1
    private int osAbi; // Target OS ABI
    private int abiVersion; // ABI version
    private int type; // Object file type
    private int machine; // Target architecture
    private int version; // Object file version
    private long entryPoint; // Entry point address
    private long programHeaderOffset; // Program header offset
    private long sectionHeaderOffset; // Section header offset
    private int flags; // Processor-specific flags
    private int headerSize; // ELF header size
    private int programHeaderEntrySize; // Size of program header entry
    private int programHeaderCount; // Number of program header entries
    private int sectionHeaderEntrySize; // Size of section header entry
    private int sectionHeaderCount; // Number of section header entries
    private int sectionNameIndex; // Section name string table index
    
    public ELFHeader(int elfClass, int dataEncoding, int fileVersion, int osAbi, 
                     int abiVersion, int type, int machine, int version, 
                     long entryPoint, long programHeaderOffset, long sectionHeaderOffset, 
                     int flags, int headerSize, int programHeaderEntrySize, 
                     int programHeaderCount, int sectionHeaderEntrySize, 
                     int sectionHeaderCount, int sectionNameIndex) {
        this.elfClass = elfClass;
        this.dataEncoding = dataEncoding;
        this.fileVersion = fileVersion;
        this.osAbi = osAbi;
        this.abiVersion = abiVersion;
        this.type = type;
        this.machine = machine;
        this.version = version;
        this.entryPoint = entryPoint;
        this.programHeaderOffset = programHeaderOffset;
        this.sectionHeaderOffset = sectionHeaderOffset;
        this.flags = flags;
        this.headerSize = headerSize;
        this.programHeaderEntrySize = programHeaderEntrySize;
        this.programHeaderCount = programHeaderCount;
        this.sectionHeaderEntrySize = sectionHeaderEntrySize;
        this.sectionHeaderCount = sectionHeaderCount;
        this.sectionNameIndex = sectionNameIndex;
    }
    
    public ELFHeaderOuterClass.ELFHeader toPB() {
        var builder = ELFHeaderOuterClass.ELFHeader.newBuilder();
        
        builder.setElfClass(elfClass);
        builder.setDataEncoding(dataEncoding);
        builder.setFileVersion(fileVersion);
        builder.setOsAbi(osAbi);
        builder.setAbiVersion(abiVersion);
        builder.setType(type);
        builder.setMachine(machine);
        builder.setVersion(version);
        builder.setEntryPoint(entryPoint);
        builder.setProgramHeaderOffset(programHeaderOffset);
        builder.setSectionHeaderOffset(sectionHeaderOffset);
        builder.setFlags(flags);
        builder.setHeaderSize(headerSize);
        builder.setProgramHeaderEntrySize(programHeaderEntrySize);
        builder.setProgramHeaderCount(programHeaderCount);
        builder.setSectionHeaderEntrySize(sectionHeaderEntrySize);
        builder.setSectionHeaderCount(sectionHeaderCount);
        builder.setSectionNameIndex(sectionNameIndex);
        
        return builder.build();
    }
}
