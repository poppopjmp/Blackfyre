package blackfyre.datatypes;

public enum DataType {
	
	 WORD(1), DWORD(2), QWORD(3), POINTER32(4), POINTER64(5);

    private int numVal;

    DataType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }

}
