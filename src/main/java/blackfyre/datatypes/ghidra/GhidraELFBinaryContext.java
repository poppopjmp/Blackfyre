package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Represents an ELF binary context in Ghidra
 */
public class GhidraELFBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraELFBinaryContext
     *
     * @param program The Ghidra program object
     * @param monitor The task monitor for tracking progress
     * @param includeDecompiledCode Whether to include decompiled code
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraELFBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // Additional ELF-specific methods would go here
}
