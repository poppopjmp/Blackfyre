package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * APK-specific binary context implementation.
 */
public class GhidraAPKBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraAPKBinaryContext.
     *
     * @param program The Ghidra program object
     * @param monitor TaskMonitor for progress reporting
     * @param includeDecompiledCode Whether to include decompiled code in the context
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraAPKBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // APK-specific functionality would be implemented here
}
