package blackfyre.datatypes;

import java.util.HashMap;

import blackfyre.protobuf.FunctionContextOuterClass;

public class InstructionContext {
    
    protected boolean theIsInitialized = false;
    
    protected long theAddress;
    
    protected String theDisassembly;
    
    // Enhanced fields
    protected String theMnemonic;
    protected HashMap<String, Object>[] theOperands;
    protected long[] theDataRefs;
    protected long[] theCodeRefs;
    
    public InstructionContext() {
        
    }
    
    public boolean initialize() {
        /*Note: This is where the members of the class will need to be appropriately initialized
         *      This should occur via the child class
         */
        
        return false;
    }
    
    public FunctionContextOuterClass.InstructionContext toPB() throws Exception {
        var instructionContext = FunctionContextOuterClass.InstructionContext.newBuilder();
        
        if (!initialize()) {
            // Had an issue initializing, so we will return an uninitialized protobuf message
            return instructionContext.build();
        }
        
        instructionContext.setAddress(theAddress);
        instructionContext.setDisassembly(theDisassembly);
        
        // Add enhanced fields if available
        if (theMnemonic != null) {
            instructionContext.setMnemonic(theMnemonic);
        }
        
        // Add operands
        if (theOperands != null) {
            for (HashMap<String, Object> operand : theOperands) {
                var operandPB = FunctionContextOuterClass.OperandContext.newBuilder();
                
                if (operand.containsKey("type")) {
                    operandPB.setType(operand.get("type").toString());
                }
                
                if (operand.containsKey("text")) {
                    operandPB.setText(operand.get("text").toString());
                }
                
                if (operand.containsKey("is_address")) {
                    operandPB.setIsAddress((Boolean)operand.get("is_address"));
                }
                
                if (operand.containsKey("value")) {
                    if (operand.get("value") instanceof Long) {
                        operandPB.setValue((Long)operand.get("value"));
                    } else if (operand.get("value") instanceof Integer) {
                        operandPB.setValue((Integer)operand.get("value"));
                    }
                }
                
                if (operand.containsKey("string_value")) {
                    operandPB.setStringValue(operand.get("string_value").toString());
                }
                
                instructionContext.addOperands(operandPB);
            }
        }
        
        // Add data references
        if (theDataRefs != null) {
            for (long ref : theDataRefs) {
                instructionContext.addDataRefs(ref);
            }
        }
        
        // Add code references
        if (theCodeRefs != null) {
            for (long ref : theCodeRefs) {
                instructionContext.addCodeRefs(ref);
            }
        }
        
        return instructionContext.build();
    }
}
