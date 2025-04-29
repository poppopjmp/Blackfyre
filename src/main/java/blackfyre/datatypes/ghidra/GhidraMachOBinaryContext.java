package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a Mach-O binary context in Ghidra
 */
public class GhidraMachOBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraMachOBinaryContext
     *
     * @param program The Ghidra program object
     * @param monitor The task monitor for tracking progress
     * @param includeDecompiledCode Whether to include decompiled code
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraMachOBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // Additional Mach-O-specific methods would go here
}
