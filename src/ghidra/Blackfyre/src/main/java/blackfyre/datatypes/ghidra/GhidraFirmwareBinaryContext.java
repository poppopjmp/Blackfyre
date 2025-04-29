package blackfyre.datatypes.ghidra;

import java.util.Properties;

import blackfyre.datatypes.FirmwareHeader;
import blackfyre.protobuf.BinaryContextOuterClass;
import blackfyre.protobuf.FirmwareHeaderOuterClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramInfo;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

public class GhidraFirmwareBinaryContext extends GhidraBinaryContext {
    
    protected Program theCurrentProgram;
    protected TaskMonitor theMonitor;
    protected FirmwareHeader theFirmwareHeader;
    
    public GhidraFirmwareBinaryContext(Program currentProgram, 
                                      TaskMonitor monitor, 
                                      boolean includeDecompiledCode, 
                                      int decompileTimeoutSeconds) {
        super(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
        
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public FirmwareHeader getFirmwareHeader() {
        return theFirmwareHeader;
    }
    
    @Override
    protected void initializeHeader() throws Exception {
        // Initialize default values
        String firmwareType = "Unknown";
        String deviceModel = "Unknown";
        String firmwareVersion = "Unknown";
        long baseAddress = 0;
        long entryPoint = 0;
        long textSectionAddress = 0;
        long textSectionSize = 0;
        long dataSectionAddress = 0;
        long dataSectionSize = 0;
        long bssSectionAddress = 0;
        long bssSectionSize = 0;
        String architecture = theCurrentProgram.getLanguage().getProcessor().toString();
        long buildTimestamp = 0;
        
        // Try to extract firmware information from program properties
        ProgramInfo programInfo = theCurrentProgram.getProgramInfo();
        if (programInfo != null) {
            Properties props = programInfo.getProperties();
            if (props != null) {
                if (props.containsKey("FIRMWARE_TYPE")) {
                    firmwareType = props.getProperty("FIRMWARE_TYPE");
                }
                if (props.containsKey("DEVICE_MODEL")) {
                    deviceModel = props.getProperty("DEVICE_MODEL");
                }
                if (props.containsKey("FIRMWARE_VERSION")) {
                    firmwareVersion = props.getProperty("FIRMWARE_VERSION");
                }
                if (props.containsKey("BUILD_TIMESTAMP")) {
                    try {
                        buildTimestamp = Long.parseLong(props.getProperty("BUILD_TIMESTAMP"));
                    } catch (NumberFormatException e) {
                        // Ignore parsing error
                    }
                }
            }
        }
        
        // Get memory information
        Memory memory = theCurrentProgram.getMemory();
        
        // Find entry point
        for (Symbol symbol : theCurrentProgram.getSymbolTable().getSymbols("entry")) {
            if (symbol != null) {
                entryPoint = symbol.getAddress().getOffset();
                break;
            }
        }
        
        // If no entry symbol found, try to get it from program
        if (entryPoint == 0) {
            entryPoint = theCurrentProgram.getImageBase().getOffset();
        }
        
        baseAddress = theCurrentProgram.getImageBase().getOffset();
        
        // Look for common memory sections
        for (MemoryBlock block : memory.getBlocks()) {
            String name = block.getName().toLowerCase();
            
            // Find text section
            if (name.contains("text") || name.contains("code")) {
                textSectionAddress = block.getStart().getOffset();
                textSectionSize = block.getSize();
            }
            // Find data section
            else if (name.contains("data") && !name.contains("uninitialized")) {
                dataSectionAddress = block.getStart().getOffset();
                dataSectionSize = block.getSize();
            }
            // Find BSS section
            else if (name.contains("bss") || 
                    (name.contains("data") && name.contains("uninitialized"))) {
                bssSectionAddress = block.getStart().getOffset();
                bssSectionSize = block.getSize();
            }
        }
        
        // Create firmware header object
        theFirmwareHeader = new FirmwareHeader(
                firmwareType, deviceModel, firmwareVersion,
                baseAddress, entryPoint,
                textSectionAddress, textSectionSize,
                dataSectionAddress, dataSectionSize,
                bssSectionAddress, bssSectionSize,
                architecture, buildTimestamp
        );
    }
    
    @Override
    public BinaryContextOuterClass.BinaryContext toPB() throws Exception {
        var binaryContextBuilder = initializeBinaryContextBuilder();
        
        FirmwareHeaderOuterClass.FirmwareHeader firmwareHeaderPB = theFirmwareHeader.toPB();
        
        binaryContextBuilder.setFirmwareHeader(firmwareHeaderPB);
        
        return binaryContextBuilder.build();
    }
}
