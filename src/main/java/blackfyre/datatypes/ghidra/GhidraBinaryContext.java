package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import blackfyre.datatypes.FileType;
import java.util.ArrayList;
import java.util.List;

public class GhidraBinaryContext {
    protected Program program;
    protected TaskMonitor monitor;
    protected boolean includeDecompiledCode;
    protected int decompileTimeoutSeconds;
    protected List<GhidraFunctionContext> functions;
    
    public GhidraBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        this.program = program;
        this.monitor = monitor;
        this.includeDecompiledCode = includeDecompiledCode;
        this.decompileTimeoutSeconds = decompileTimeoutSeconds;
        this.functions = new ArrayList<>();
    }
    
    public static FileType getFileTypeFromGhidra(Program program) {
        String format = program.getExecutableFormat();
        if (format.contains("PE")) {
            if (program.getAddressFactory().getDefaultAddressSpace().getSize() == 64) {
                return FileType.PE64;
            } else {
                return FileType.PE32;
            }
        } else if (format.contains("ELF")) {
            if (program.getAddressFactory().getDefaultAddressSpace().getSize() == 64) {
                return FileType.ELF64;
            } else {
                return FileType.ELF32;
            }
        } else if (format.contains("Mach-O")) {
            if (program.getAddressFactory().getDefaultAddressSpace().getSize() == 64) {
                return FileType.MACHO64;
            } else {
                return FileType.MACHO32;
            }
        }
        return FileType.UNKNOWN;
    }
    
    // Additional methods to process binary data
    public void analyze() {
        // Base implementation
    }
    
    public List<GhidraFunctionContext> getFunctions() {
        return functions;
    }
}
