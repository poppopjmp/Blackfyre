package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a firmware binary context in Ghidra
 */
public class GhidraFirmwareBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraFirmwareBinaryContext
     *
     * @param program The Ghidra program object
     * @param monitor The task monitor for tracking progress
     * @param includeDecompiledCode Whether to include decompiled code
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraFirmwareBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // Additional firmware-specific methods would go here
}
