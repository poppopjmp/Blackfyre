package blackfyre.datatypes;

import blackfyre.protobuf.MachOHeaderOuterClass;

public class MachOHeader {
    private int magic; // Magic number identifying the file
    private int cpuType; // CPU type
    private int cpuSubType; // CPU subtype
    private int fileType; // File type
    private int commandCount; // Number of load commands
    private int commandSize; // Size of all load commands
    private int flags; // Flags
    private int reserved; // Reserved field (64-bit only)
    private long textSegmentAddress; // Text segment address
    private long textSegmentSize; // Text segment size
    private long dataSegmentAddress; // Data segment address
    private long dataSegmentSize; // Data segment size
    
    public MachOHeader(int magic, int cpuType, int cpuSubType, int fileType, 
                       int commandCount, int commandSize, int flags, int reserved, 
                       long textSegmentAddress, long textSegmentSize,
                       long dataSegmentAddress, long dataSegmentSize) {
        this.magic = magic;
        this.cpuType = cpuType;
        this.cpuSubType = cpuSubType;
        this.fileType = fileType;
        this.commandCount = commandCount;
        this.commandSize = commandSize;
        this.flags = flags;
        this.reserved = reserved;
        this.textSegmentAddress = textSegmentAddress;
        this.textSegmentSize = textSegmentSize;
        this.dataSegmentAddress = dataSegmentAddress;
        this.dataSegmentSize = dataSegmentSize;
    }
    
    public MachOHeaderOuterClass.MachOHeader toPB() {
        var builder = MachOHeaderOuterClass.MachOHeader.newBuilder();
        
        builder.setMagic(magic);
        builder.setCpuType(cpuType);
        builder.setCpuSubType(cpuSubType);
        builder.setFileType(fileType);
        builder.setCommandCount(commandCount);
        builder.setCommandSize(commandSize);
        builder.setFlags(flags);
        builder.setReserved(reserved);
        builder.setTextSegmentAddress(textSegmentAddress);
        builder.setTextSegmentSize(textSegmentSize);
        builder.setDataSegmentAddress(dataSegmentAddress);
        builder.setDataSegmentSize(dataSegmentSize);
        
        return builder.build();
    }
}
