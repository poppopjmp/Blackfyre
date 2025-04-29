package blackfyre.datatypes;

public enum WordSize {
    
    BITS_16(1), BITS_32(2), BITS_64(3);
    
    private int numVal;

    WordSize(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
}
