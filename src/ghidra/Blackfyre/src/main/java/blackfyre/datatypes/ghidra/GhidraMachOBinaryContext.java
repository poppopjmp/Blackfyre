package blackfyre.datatypes.ghidra;

import java.io.File;
import java.util.List;

import blackfyre.datatypes.MachOHeader;
import blackfyre.protobuf.BinaryContextOuterClass;
import blackfyre.protobuf.MachOHeaderOuterClass;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.MachHeader.MagicType;
import ghidra.app.util.bin.format.macho.MachO;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.LoadCommand;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GhidraMachOBinaryContext extends GhidraBinaryContext {
    
    private boolean theIsInitialized = false;
    protected Program theCurrentProgram;
    protected TaskMonitor theMonitor;
    protected MachOHeader theMachOHeader;
    
    public GhidraMachOBinaryContext(Program currentProgram, 
                                  TaskMonitor monitor, 
                                  boolean includeDecompiledCode, 
                                  int decompileTimeoutSeconds) {
        super(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
        
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public MachOHeader getMachOHeader() {
        return theMachOHeader;
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
        
        // Create the Mach-O object
        MachO machO = new MachO(provider);
        
        // Get the Mach-O header
        MachHeader machHeader = machO.getMachHeader();
        
        // Extract header information
        int magic = machHeader.getMagic();
        int cpuType = machHeader.getCpuType();
        int cpuSubType = machHeader.getCpuSubType();
        int fileType = machHeader.getFileType();
        int commandCount = machHeader.getCommandCount();
        int commandSize = machHeader.getCommandSize();
        int flags = machHeader.getFlags();
        int reserved = (machHeader.getMagicType() == MagicType.MAGIC_64) ? machHeader.getReserved() : 0;
        
        // Initialize segment info
        long textSegmentAddress = 0;
        long textSegmentSize = 0;
        long dataSegmentAddress = 0;
        long dataSegmentSize = 0;
        
        // Get segment information from load commands
        List<LoadCommand> loadCommands = machO.getLoadCommands();
        for (LoadCommand cmd : loadCommands) {
            if (cmd instanceof SegmentCommand) {
                SegmentCommand segCmd = (SegmentCommand) cmd;
                String segName = segCmd.getSegmentName();
                
                if ("__TEXT".equals(segName)) {
                    textSegmentAddress = segCmd.getVMaddress();
                    textSegmentSize = segCmd.getVMsize();
                } 
                else if ("__DATA".equals(segName)) {
                    dataSegmentAddress = segCmd.getVMaddress();
                    dataSegmentSize = segCmd.getVMsize();
                }
            }
        }
        
        // Create the Mach-O header object
        theMachOHeader = new MachOHeader(magic, cpuType, cpuSubType, fileType, 
                                        commandCount, commandSize, flags, reserved, 
                                        textSegmentAddress, textSegmentSize,
                                        dataSegmentAddress, dataSegmentSize);
        
        provider.close();
    }
    
    @Override
    public BinaryContextOuterClass.BinaryContext toPB() throws Exception {
        var binaryContextBuilder = initializeBinaryContextBuilder();
        
        MachOHeaderOuterClass.MachOHeader machOHeaderPB = theMachOHeader.toPB();
        
        binaryContextBuilder.setMachOHeader(machOHeaderPB);
        
        return binaryContextBuilder.build();
    }
}
