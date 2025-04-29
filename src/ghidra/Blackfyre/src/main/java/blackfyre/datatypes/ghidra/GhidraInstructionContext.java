package blackfyre.datatypes.ghidra;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.ProgramLocation;

import blackfyre.datatypes.InstructionContext;

public class GhidraInstructionContext extends InstructionContext {
    
    private Program theCurrentProgram;
    private Instruction theInstruction;
    
    public GhidraInstructionContext(Program currentProgram, Instruction instruction) {
        theCurrentProgram = currentProgram;
        theInstruction = instruction;
    }
    
    @Override
    public boolean initialize() {
        if (theIsInitialized) {
            return theIsInitialized;
        }
        
        try {
            theAddress = theInstruction.getAddress().getOffset();
            theDisassembly = theInstruction.toString();
            theMnemonic = theInstruction.getMnemonicString();
            
            // Enhanced operand analysis
            theOperands = getOperandsFromGhidra();
            
            // Get code and data references
            theDataRefs = getDataRefsFromGhidra();
            theCodeRefs = getCodeRefsFromGhidra();
            
            theIsInitialized = true;
        } catch (Exception e) {
            System.err.println("Error initializing instruction context: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
        
        return theIsInitialized;
    }
    
    private HashMap<String, Object>[] getOperandsFromGhidra() {
        int count = theInstruction.getNumOperands();
        ArrayList<HashMap<String, Object>> operands = new ArrayList<>();
        
        for (int i = 0; i < count; i++) {
            HashMap<String, Object> operand = new HashMap<>();
            
            // Get operand type
            int type = theInstruction.getOperandType(i);
            operand.put("type", getOperandTypeName(type));
            
            // Get the operand as string
            String text = theInstruction.getDefaultOperandRepresentation(i);
            operand.put("text", text);
            
            // Check if operand is an address
            boolean isAddress = (type & OperandType.ADDRESS) != 0;
            operand.put("is_address", isAddress);
            
            // Get value if it's a scalar or address
            if ((type & OperandType.SCALAR) != 0) {
                Scalar scalar = theInstruction.getScalar(i);
                if (scalar != null) {
                    operand.put("value", scalar.getValue());
                }
            }
            
            // Check for string references
            if (isAddress || (type & OperandType.SCALAR) != 0) {
                Reference[] refs = theInstruction.getOperandReferences(i);
                for (Reference ref : refs) {
                    Address refAddr = ref.getToAddress();
                    
                    // Check if it points to a string
                    String potentialString = DataUtilities.getPotentialString(
                        theCurrentProgram, 
                        refAddr, 
                        -1, 
                        true
                    );
                    
                    if (potentialString != null) {
                        operand.put("string_value", potentialString);
                        break;
                    }
                }
            }
            
            operands.add(operand);
        }
        
        @SuppressWarnings("unchecked")
        HashMap<String, Object>[] result = new HashMap[operands.size()];
        return operands.toArray(result);
    }
    
    private String getOperandTypeName(int type) {
        ArrayList<String> types = new ArrayList<>();
        
        if ((type & OperandType.REGISTER) != 0) types.add("register");
        if ((type & OperandType.IMMEDIATE) != 0) types.add("immediate");
        if ((type & OperandType.ADDRESS) != 0) types.add("address");
        if ((type & OperandType.SCALAR) != 0) types.add("scalar");
        if ((type & OperandType.DYNAMIC) != 0) types.add("dynamic");
        
        if (types.isEmpty()) return "unknown";
        return String.join(",", types);
    }
    
    private long[] getDataRefsFromGhidra() {
        ArrayList<Long> refs = new ArrayList<>();
        ReferenceManager refManager = theCurrentProgram.getReferenceManager();
        
        Reference[] references = refManager.getReferencesFrom(theInstruction.getAddress());
        for (Reference ref : references) {
            if (!ref.getReferenceType().isFlow()) {
                refs.add(ref.getToAddress().getOffset());
            }
        }
        
        // Convert to primitive long array
        long[] result = new long[refs.size()];
        for (int i = 0; i < refs.size(); i++) {
            result[i] = refs.get(i);
        }
        
        return result;
    }
    
    private long[] getCodeRefsFromGhidra() {
        ArrayList<Long> refs = new ArrayList<>();
        ReferenceManager refManager = theCurrentProgram.getReferenceManager();
        
        Reference[] references = refManager.getReferencesFrom(theInstruction.getAddress());
        for (Reference ref : references) {
            if (ref.getReferenceType().isFlow() && !ref.isEntryPointReference()) {
                refs.add(ref.getToAddress().getOffset());
            }
        }
        
        // Convert to primitive long array
        long[] result = new long[refs.size()];
        for (int i = 0; i < refs.size(); i++) {
            result[i] = refs.get(i);
        }
        
        return result;
    }
    
    // Additional member variables
    private String theMnemonic;
    private HashMap<String, Object>[] theOperands;
    private long[] theDataRefs;
    private long[] theCodeRefs;
    
    // Getters
    public String getMnemonic() {
        return theMnemonic;
    }
    
    public HashMap<String, Object>[] getOperands() {
        return theOperands;
    }
    
    public long[] getDataRefs() {
        return theDataRefs;
    }
    
    public long[] getCodeRefs() {
        return theCodeRefs;
    }
}
