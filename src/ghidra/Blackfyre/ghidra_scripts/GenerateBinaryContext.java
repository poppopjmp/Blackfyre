
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.common.io.Files;

import blackfyre.datatypes.FileType;
import blackfyre.datatypes.ghidra.GhidraBinaryContext;
import blackfyre.datatypes.ghidra.GhidraPEBinaryContext;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.headless.HeadlessScript;

public class GenerateBinaryContext extends HeadlessScript {
	
	public int DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 30;
	
	@Override
	public void run() throws Exception 
	{	
		
		File outputDirectory;
        boolean includeRawBinary;
        boolean includeDecompiledCode;
        int decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;

        // Check if arguments have been passed in
        String[] args = getScriptArgs();
        if (args.length > 0) 
        {
            outputDirectory = new File(args[0]);
            includeRawBinary = Boolean.parseBoolean(args[1]);
            includeDecompiledCode = Boolean.parseBoolean(args[2]);
            
            if( analysisTimeoutOccurred())
			{				
				println("Skipping the generation of the binary context because of analysis timeout occurred: "+currentProgram.getName());
								
				return;
			}

            if (args.length > 3) 
            {
                try {
                    decompileTimeoutSeconds = Integer.parseInt(args[3]);
                } catch (NumberFormatException e) {
                    println("Invalid timeout value. Using default " + DEFAULT_DECOMPILE_TIMEOUT_SECONDS + " seconds.");
                }
            }                  
        }	
		else
		{
			outputDirectory = askDirectory("Choose Folder to Output Binary Context Container", "OK");
            includeRawBinary = askYesNo("Binary Context Container", "Include raw binary?");
            includeDecompiledCode = askYesNo("Decompiled Code", "Include function decompiled code?");
            if(includeDecompiledCode)
            {
            	decompileTimeoutSeconds = askInt("Decompile Timeout", "Enter the timeout (recommended 30) for decompiling functions (in seconds):");  
            	
            }
    	}

							
		FileType fileType = GhidraBinaryContext.getFileTypeFromGhidra(currentProgram);
			
		
		GhidraBinaryContext ghidraBinaryContext = null;
		
		if(fileType == FileType.PE32 || fileType == FileType.PE64)
		{
			ghidraBinaryContext = new GhidraPEBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
		}
		else
		{
			ghidraBinaryContext =  new GhidraBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
		}
		ghidraBinaryContext.initialize();
		
		
		String message = String.format("Generating Binary Context Container: %s (sha-256: %s)", 
				                        ghidraBinaryContext.getName(), 
				                        ghidraBinaryContext.getSHA256Hash());
		println(message);
		
		message = ghidraBinaryContext.toBytesAndWriteToFile(outputDirectory.getAbsolutePath(), includeRawBinary, includeDecompiledCode);
		println(message);
					
	}
	
}
