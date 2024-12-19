
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class PrescriptDisableAnalysisOptions extends GhidraScript {
	
	private static final String DECOMPILER_PARAM_ID = "Decompiler Parameter ID";	
	private static final String DECOMPILER_SWITCH_ANALYSIS = "Decompiler Switch Analysis";
	
	private static final String WIN_x86_PE_RTTI_ANALYSIS = "Windows x86 PE RTTI Analyzer";
	
	@Override
	public void run() throws Exception 
	{	
					
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (options.containsKey(DECOMPILER_PARAM_ID)) 
		{
			setAnalysisOption(currentProgram, DECOMPILER_PARAM_ID, "false");
		}
		if (options.containsKey(DECOMPILER_SWITCH_ANALYSIS)) 
		{
			setAnalysisOption(currentProgram, DECOMPILER_SWITCH_ANALYSIS, "false");
		}
		if (options.containsKey(WIN_x86_PE_RTTI_ANALYSIS)) 
		{
			setAnalysisOption(currentProgram, WIN_x86_PE_RTTI_ANALYSIS, "false");
		}
		
	}


}
