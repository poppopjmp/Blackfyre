package blackfyre.datatypes;

public enum MessageType {
    
    BINARY_CONTEXT_MSG(1),
    FUNCTION_CONTEXT_MSG(2),
	RAW_BINARY_MSG(3);
    
    private int numVal;

    MessageType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
