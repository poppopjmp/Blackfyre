package blackfyre.datatypes.ghidra;

import java.io.File;

import blackfyre.datatypes.ELFHeader;
import blackfyre.protobuf.BinaryContextOuterClass;
import blackfyre.protobuf.ELFHeaderOuterClass;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GhidraELFBinaryContext extends GhidraBinaryContext {
    
    private boolean theIsInitialized = false;
    protected Program theCurrentProgram;
    protected TaskMonitor theMonitor;
    protected ELFHeader theELFHeader;
    
    public GhidraELFBinaryContext(Program currentProgram, 
                                TaskMonitor monitor, 
                                boolean includeDecompiledCode, 
                                int decompileTimeoutSeconds) {
        super(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
        
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public ELFHeader getELFHeader() {
        return theELFHeader;
    }
    
    @Override
    protected void initializeHeader() throws Exception {
        File exePath = new File(theCurrentProgram.getExecutablePath());
        String path = exePath.getAbsolutePath();

        // Set up the appropriate file prefix based on OS
        String prefix = "file://";
        if (path.startsWith("/")) {
            prefix = "file:/";
        }
        FSRL fsrl = FSRL.fromString(prefix + path);

        FileByteProvider provider = new FileByteProvider(exePath, fsrl, java.nio.file.AccessMode.READ);
        
        // Create the ELF header object
        ElfHeader elfHeader = ElfHeader.createElfHeader(provider);
        
        // Extract ELF header information
        int elfClass = elfHeader.is32Bit() ? 1 : 2;
        int dataEncoding = elfHeader.isLittleEndian() ? 1 : 2;
        int fileVersion = elfHeader.e_version();
        int osAbi = elfHeader.e_ident()[ElfHeader.EI_OSABI] & 0xff;
        int abiVersion = elfHeader.e_ident()[ElfHeader.EI_ABIVERSION] & 0xff;
        int type = elfHeader.e_type();
        int machine = elfHeader.e_machine();
        int version = elfHeader.e_version();
        long entryPoint = elfHeader.e_entry();
        long programHeaderOffset = elfHeader.e_phoff();
        long sectionHeaderOffset = elfHeader.e_shoff();
        int flags = elfHeader.e_flags();
        int headerSize = elfHeader.e_ehsize();
        int programHeaderEntrySize = elfHeader.e_phentsize();
        int programHeaderCount = elfHeader.e_phnum();
        int sectionHeaderEntrySize = elfHeader.e_shentsize();
        int sectionHeaderCount = elfHeader.e_shnum();
        int sectionNameIndex = elfHeader.e_shstrndx();
        
        // Create the ELF header object
        theELFHeader = new ELFHeader(elfClass, dataEncoding, fileVersion, osAbi, 
                                    abiVersion, type, machine, version, 
                                    entryPoint, programHeaderOffset, sectionHeaderOffset, 
                                    flags, headerSize, programHeaderEntrySize, 
                                    programHeaderCount, sectionHeaderEntrySize, 
                                    sectionHeaderCount, sectionNameIndex);
        
        provider.close();
    }
    
    @Override
    public BinaryContextOuterClass.BinaryContext toPB() throws Exception {
        var binaryContextBuilder = initializeBinaryContextBuilder();
        
        ELFHeaderOuterClass.ELFHeader elfHeaderPB = theELFHeader.toPB();
        
        binaryContextBuilder.setElfHeader(elfHeaderPB);
        
        return binaryContextBuilder.build();
    }
}
