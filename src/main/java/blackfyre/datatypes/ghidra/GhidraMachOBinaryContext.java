package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Mach-O-specific binary context implementation.
 */
public class GhidraMachOBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraMachOBinaryContext.
     *
     * @param program The Ghidra program object
     * @param monitor TaskMonitor for progress reporting
     * @param includeDecompiledCode Whether to include decompiled code in the context
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraMachOBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // Mach-O-specific functionality would be implemented here
}
