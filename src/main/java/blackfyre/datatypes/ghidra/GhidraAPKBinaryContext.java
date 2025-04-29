package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Represents an APK binary context in Ghidra
 */
public class GhidraAPKBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraAPKBinaryContext
     *
     * @param program The Ghidra program object
     * @param monitor The task monitor for tracking progress
     * @param includeDecompiledCode Whether to include decompiled code
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraAPKBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // Additional APK-specific methods would go here
}
