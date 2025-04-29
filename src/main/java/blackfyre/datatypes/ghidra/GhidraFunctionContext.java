package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Function;

/**
 * Represents context information for a Ghidra function.
 */
public class GhidraFunctionContext {
    private Function function;
    
    /**
     * Constructor for GhidraFunctionContext.
     *
     * @param function The Ghidra Function object
     */
    public GhidraFunctionContext(Function function) {
        this.function = function;
    }
    
    /**
     * Gets the underlying Ghidra function.
     *
     * @return The Ghidra function
     */
    public Function getFunction() {
        return function;
    }
    
    /**
     * Gets the function name.
     *
     * @return The function name
     */
    public String getName() {
        return function.getName();
    }
    
    /**
     * Gets the function entry point address.
     *
     * @return The entry point address as a string
     */
    public String getEntryPoint() {
        return function.getEntryPoint().toString();
    }
}
