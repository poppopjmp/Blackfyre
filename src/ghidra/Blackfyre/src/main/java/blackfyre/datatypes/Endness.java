package blackfyre.datatypes;

public enum Endness {
    
    LITTLE_ENDIAN(1), BIG_ENDIAN(2);
    
    private int numVal;

    Endness(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
}
