package blackfyre.datatypes;

public enum FileType {

    PE32(1), PE64(2), ELF32(3), ELF64(4), MACH_O_32(5), MACH_O_64(6);

    private int numVal;

    FileType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
