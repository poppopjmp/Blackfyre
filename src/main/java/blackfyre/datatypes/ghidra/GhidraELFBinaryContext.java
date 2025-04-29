package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * ELF-specific binary context implementation.
 */
public class GhidraELFBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraELFBinaryContext.
     *
     * @param program The Ghidra program object
     * @param monitor TaskMonitor for progress reporting
     * @param includeDecompiledCode Whether to include decompiled code in the context
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraELFBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // ELF-specific functionality would be implemented here
}
