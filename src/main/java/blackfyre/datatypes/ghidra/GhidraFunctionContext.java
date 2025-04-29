package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class GhidraFunctionContext {
    private String name;
    private String decompiledCode;
    private Address entryPoint;
    private long entryPointOffset;
    
    public GhidraFunctionContext(Function function, String decompiledCode) {
        this.name = function.getName();
        this.decompiledCode = decompiledCode;
        this.entryPoint = function.getEntryPoint();
        this.entryPointOffset = entryPoint.getOffset();
    }
    
    public String getName() {
        return name;
    }
    
    public String getDecompiledCode() {
        return decompiledCode;
    }
    
    public Address getEntryPoint() {
        return entryPoint;
    }
    
    public long getEntryPointOffset() {
        return entryPointOffset;
    }
}
