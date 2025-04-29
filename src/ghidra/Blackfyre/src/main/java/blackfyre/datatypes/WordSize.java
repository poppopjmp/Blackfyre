package blackfyre.datatypes;

public enum WordSize {

    BITS_32(1), BITS_64(2), BITS_16(3);

    private int numVal;

    WordSize(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
}
