package blackfyre.datatypes;

public enum Endness {

    BIG_ENDIAN(1), LITTLE_ENDIAN(2);

    private int numVal;

    Endness(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
