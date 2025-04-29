package blackfyre.datatypes.ghidra;

import blackfyre.datatypes.FileType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for all binary context implementations in Ghidra.
 */
public class GhidraBinaryContext {
    protected Program program;
    protected TaskMonitor monitor;
    protected boolean includeDecompiledCode;
    protected int decompileTimeoutSeconds;

    /**
     * Constructor for GhidraBinaryContext.
     *
     * @param program The Ghidra program object
     * @param monitor TaskMonitor for progress reporting
     * @param includeDecompiledCode Whether to include decompiled code in the context
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        this.program = program;
        this.monitor = monitor;
        this.includeDecompiledCode = includeDecompiledCode;
        this.decompileTimeoutSeconds = decompileTimeoutSeconds;
    }
    
    /**
     * Determines the file type from a Ghidra program.
     *
     * @param program The Ghidra program to examine
     * @return The detected FileType
     */
    public static FileType getFileTypeFromGhidra(Program program) {
        if (program == null) {
            return FileType.UNKNOWN;
        }

        // Check executable format based on program properties
        // This is a simplified implementation - actual implementation would need to
        // examine program headers and properties in more detail
        String format = program.getExecutableFormat();
        if (format != null) {
            if (format.contains("PE")) {
                boolean is64bit = program.getDefaultPointerSize() == 8;
                return is64bit ? FileType.PE64 : FileType.PE32;
            } else if (format.contains("ELF")) {
                boolean is64bit = program.getDefaultPointerSize() == 8;
                return is64bit ? FileType.ELF64 : FileType.ELF32;
            } else if (format.contains("Mach-O")) {
                boolean is64bit = program.getDefaultPointerSize() == 8;
                return is64bit ? FileType.MACH_O_64 : FileType.MACH_O_32;
            }
        }
        
        // Additional logic could be added for detecting APK and FIRMWARE formats
        
        return FileType.UNKNOWN;
    }
}
