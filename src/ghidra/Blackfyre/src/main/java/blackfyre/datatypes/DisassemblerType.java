package blackfyre.datatypes;

public enum DisassemblerType {
	
	Ghidra(1), IDAPro(2), BinaryNinja(3);

    private int numVal;

	DisassemblerType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
