package blackfyre.datatypes.ghidra;

import ghidra.program.model.listing.Function;

/**
 * Represents a function context in Ghidra
 */
public class GhidraFunctionContext {
    private Function function;
    
    /**
     * Constructor for GhidraFunctionContext
     *
     * @param function The Ghidra function object
     */
    public GhidraFunctionContext(Function function) {
        this.function = function;
    }
    
    /**
     * Gets the Ghidra function object
     *
     * @return The function object
     */
    public Function getFunction() {
        return function;
    }
    
    /**
     * Gets the name of the function
     *
     * @return The function name
     */
    public String getName() {
        return function.getName();
    }
    
    /**
     * Gets the entry point address of the function as a string
     *
     * @return The entry point address string
     */
    public String getEntryPoint() {
        return function.getEntryPoint().toString();
    }
}
