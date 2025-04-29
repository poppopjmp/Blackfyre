package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class GhidraPEBinaryContext extends GhidraBinaryContext {
    
    public GhidraPEBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        super(program, monitor, includeDecompiledCode, decompileTimeoutSeconds);
    }
    
    @Override
    public void analyze() {
        // PE-specific analysis implementation
        // Process PE headers, sections, etc.
    }
    
    // Additional PE-specific methods
}
