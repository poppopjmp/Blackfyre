package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * PE-specific binary context implementation.
 */
public class GhidraPEBinaryContext extends GhidraBinaryContext {
    
    /**
     * Constructor for GhidraPEBinaryContext.
     *
     * @param program The Ghidra program object
     * @param monitor TaskMonitor for progress reporting
     * @param includeDecompiledCode Whether to include decompiled code in the context
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraPEBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    // PE-specific functionality would be implemented here
}
