package blackfyre.datatypes;

// See https://stackoverflow.com/questions/8811815/is-it-possible-to-assign-numeric-value-to-an-enum-in-java

public enum ProcessorType {

    x86(1), x86_64(2), ARM(3), PPC(4), MIPS(5), AARCH64(6);

    private int numVal;

    ProcessorType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
