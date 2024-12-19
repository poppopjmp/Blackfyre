import java.util.ArrayList;
import java.util.HashMap;

import blackfyre.datatypes.ghidra.GhidraFunctionContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;

public class GetFunctionXrefs extends GhidraScript {
	
	@Override
	public void run() throws Exception {
		println("Hello World");
		
		HashMap<Long,ArrayList<Long>>  callerMap = getCallerMapFromGhidra();
		
		HashMap<Long,ArrayList<Long>>  calleeMap = getCalleeMap(callerMap);
		
		FunctionManager functionManager = currentProgram.getFunctionManager();
				
		
		
		AddressFactory addrFactory = currentProgram.getAddressFactory();
		
		Address address = addrFactory.getAddress("0x10001200");
		
		for(var calleeEntry: calleeMap.entrySet())
		{
			
			Address callerAddress = address.getNewAddress(calleeEntry.getKey());
			
			println(String.format("\nCaller: %s ", functionManager.getFunctionAt(callerAddress).getName()));
			
			for(var callee: calleeEntry.getValue())
			{
				Address calleeAddress = address.getNewAddress(callee);
				
				println(String.format("\tCallee: %s ", functionManager.getFunctionAt(calleeAddress).getName()));
			}
		}
		

		
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
			
		
		
		
		//Address address = addrFactory.getAddress("0x100016fc");
		address = addrFactory.getAddress("0x10001200");
		
		
		Function function = functionManager.getFunctionAt(address);
		
		print("Function name: "+function.getName());
		
		for(var reference : referenceManager.getReferencesTo(address))
		{
			/* Note:   The 'getReferencesTo' provides the address FROM the site where the TO is referenced; get  the callers
			 *        Example:
			 *                 getReferenceTo(0x100016fc)
			 *                 
			 *                 Output --> From: (0x10001038)  To: (0x100016FC) (GhidraScript)
			 *                            From: (0x1000105C)  To: (0x100016FC) (GhidraScript) 
			 *                            
 *                            The functions at 0x10001038 and 0x1000105C reference the function 0x100016FC
 *                            In particular, 0x10001038 and 0x1000105C  are callers of the function 0x100016FC
			 *                         
			 * 
			 */
			
			Address toAddress = reference.getToAddress();
			
			Address  fromAddress = reference.getFromAddress();
						
			
			String message = String.format("(getReferencesTo) From: (0x%08X)  To: (0x%08X)", fromAddress.getOffset(), toAddress.getOffset() );
			
			println(message);
		
		}
		address = addrFactory.getAddress("0x10001208");
		
		for(var reference : referenceManager.getReferencesFrom(address))
		{
			/* Note:  Retrieves the callees of the target function
			 *                         
			 *        Example: getReferencesFrom(0x10001208)
			 *        
			 *        			10001208 e8 c3 04        CALL       __alloca_probe   undefined __alloca_probe(void)        
			 *        		   
			 *                  Output--> From: (0x10001208)  To: (0x100016D0)
			 *                  
			 *                  __alloca_prob --> 0x100016D0
			 */
			
			Address toAddress = reference.getToAddress();
			
			Address  fromAddress = reference.getFromAddress();
						
			
			String message = String.format("(getReferencesFrom) From: (0x%08X)  To: (0x%08X)", fromAddress.getOffset(), toAddress.getOffset() );
			
			println(message);
		
		}
		

		
		
		//Function function = functionManager.getFunctionAt();
		
//		for( Function ghidraFunction : currentProgram.getFunctionManager().getFunctions(true))
//		{
//			
//			
//						
//		}
//		
		
		
	}
	
	protected HashMap<Long, ArrayList<Long>>  getCalleeMap(HashMap<Long, ArrayList<Long>> callerMap)
	{
		// From the caller map, we can derive the callee map
		HashMap<Long, ArrayList<Long>> calleeMap = new HashMap<Long, ArrayList<Long>>();
		
		for( var callerEntry: callerMap.entrySet() )
		{
			//ArrayList<Long> calleeList  = new ArrayList<Long>();
			
			Long calleeAddress = callerEntry.getKey();
			
			for ( var callerAddress : callerEntry.getValue())
			{
				
				ArrayList<Long> calleeList  = calleeMap.get(callerAddress);
				// Check if the ArrayList has been initialized
				if(calleeList == null)
				{
					calleeList  = new ArrayList<Long>();
					
					// Add the key:list pair to the map
					calleeMap.put(callerAddress, calleeList);
				}
				
				// Add the callee address to the list
				calleeList.add(calleeAddress);	
				
				println(String.format("\tCaller (0x%08X) --> Callee (0x%08X) ", callerAddress, calleeAddress));
			}
						
		}
		
		return calleeMap;
	}
	
	
    protected HashMap<Long,ArrayList<Long> >  getCallerMapFromGhidra()
    {
    	
    	HashMap<Long,ArrayList<Long>> callerMap = new HashMap<Long,ArrayList<Long>>();
    	
    	ReferenceManager referenceManager = currentProgram.getReferenceManager();
    	
    	FunctionManager functionManager = currentProgram.getFunctionManager();
    	    	
    	
    	// Iterate of each function to get its callers
    	for( Function ghidraFunction : currentProgram.getFunctionManager().getFunctions(true))
		{
    		
    		Long functionAddress = ghidraFunction.getEntryPoint().getOffset();
    		
    		ArrayList<Long> callerList = new ArrayList<Long>() ;
    		
			println(String.format("(0x%08X) %s", functionAddress, ghidraFunction.getName()));
			
    		
    		// Get the callers of the current function
    		for ( var reference: referenceManager.getReferencesTo(ghidraFunction.getEntryPoint())) 
    		{
    			
    			// Caller's address    			    			
    			Address callerAddress = reference.getFromAddress();
    			    			
    			
    			// Check that the caller address is a function
    			Function callerFunction = functionManager.getFunctionContaining(callerAddress);
    			if(callerFunction == null)
    			{
    				// Address does not belong to address, go to the next reference
    				println(String.format("\tCaller (0x%08X) is not a function", callerAddress.getOffset()));
    				continue;
    			}
    			println(String.format("\tCaller (0x%08X) %s", callerFunction.getEntryPoint().getOffset(), callerFunction.getName()));
    			
    			
    			// Add the caller's address to the list
    			callerList.add(callerFunction.getEntryPoint().getOffset());
    			
    		}
    		
    		// Add the caller information of the target function to the map
    		callerMap.put(functionAddress, callerList);
 							
		}
 	
    	return callerMap;
    }
	
	
	private Address addr(String address, Program program) {
		AddressFactory addrFactory = program.getAddressFactory();
		return addrFactory.getAddress(address);
	}

}
