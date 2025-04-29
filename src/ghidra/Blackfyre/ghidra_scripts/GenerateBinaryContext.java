import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

import com.google.common.io.Files;

import blackfyre.datatypes.FileType;
import blackfyre.datatypes.ghidra.GhidraBinaryContext;
import blackfyre.datatypes.ghidra.GhidraPEBinaryContext;
import blackfyre.datatypes.ghidra.GhidraELFBinaryContext;
import blackfyre.datatypes.ghidra.GhidraMachOBinaryContext;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.headless.HeadlessScript;

public class GenerateBinaryContext extends HeadlessScript {

    public int DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 30;
    public static final String DEFAULT_FUNCTION_FILTER = ".*";

    @Override
    public void run() throws Exception {

        Path outputDirectoryPath;
        boolean includeRawBinary;
        boolean includeDecompiledCode;
        int decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        String functionFilter = DEFAULT_FUNCTION_FILTER;
        boolean includeExtendedMetadata = false;

        // Check if arguments have been passed in
        String[] args = getScriptArgs();
        if (args.length > 0) {
            outputDirectoryPath = Paths.get(args[0]).normalize();
            includeRawBinary = Boolean.parseBoolean(args[1]);
            includeDecompiledCode = Boolean.parseBoolean(args[2]);

            if (analysisTimeoutOccurred()) {
                println("Skipping the generation of the binary context because of analysis timeout occurred: " + currentProgram.getName());
                return;
            }

            if (args.length > 3) {
                try {
                    decompileTimeoutSeconds = Integer.parseInt(args[3]);
                } catch (NumberFormatException e) {
                    println("Invalid timeout value. Using default " + DEFAULT_DECOMPILE_TIMEOUT_SECONDS + " seconds.");
                }
            }

            if (args.length > 4) {
                functionFilter = args[4];
                try {
                    Pattern.compile(functionFilter); // Validate regex pattern
                } catch (Exception e) {
                    println("Invalid function filter regex. Using default pattern (.*) to include all functions.");
                    functionFilter = DEFAULT_FUNCTION_FILTER;
                }
            }

            if (args.length > 5) {
                includeExtendedMetadata = Boolean.parseBoolean(args[5]);
            }
        } else {
            // Ask for input interactively
            File outputDir = askDirectory("Choose Folder to Output Binary Context Container", "OK");
            outputDirectoryPath = outputDir.toPath().normalize();
            includeRawBinary = askYesNo("Binary Context Container", "Include raw binary?");
            includeDecompiledCode = askYesNo("Decompiled Code", "Include function decompiled code?");
            if (includeDecompiledCode) {
                decompileTimeoutSeconds = askInt("Decompile Timeout", "Enter the timeout (recommended 30) for decompiling functions (in seconds):");
                functionFilter = askString("Function Filter", "Enter regex pattern to filter functions (leave empty for all):", DEFAULT_FUNCTION_FILTER);
            }
            includeExtendedMetadata = askYesNo("Extended Metadata", "Include extended metadata (symbols, strings, imports/exports)?");
        }

        // Determine the file type using Ghidra
        FileType fileType = GhidraBinaryContext.getFileTypeFromGhidra(currentProgram);

        // Create the appropriate GhidraBinaryContext object
        GhidraBinaryContext ghidraBinaryContext = null;

        try {
            monitor.setMessage("Initializing binary context...");
            
            if (fileType == FileType.PE32 || fileType == FileType.PE64) {
                ghidraBinaryContext = new GhidraPEBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
            } else if (fileType == FileType.ELF32 || fileType == FileType.ELF64) {
                ghidraBinaryContext = new GhidraELFBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
            } else if (fileType == FileType.MACHO32 || fileType == FileType.MACHO64) {
                ghidraBinaryContext = new GhidraMachOBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
            } else {
                ghidraBinaryContext = new GhidraBinaryContext(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
            }

            monitor.setMessage("Setting configuration options...");
            ghidraBinaryContext.setFunctionFilter(functionFilter);
            ghidraBinaryContext.setIncludeExtendedMetadata(includeExtendedMetadata);
            
            monitor.setMessage("Initializing binary context...");
            monitor.initialize(100);
            ghidraBinaryContext.initialize();

            String message = String.format("Generating Binary Context Container: %s (sha-256: %s)",
                    ghidraBinaryContext.getName(),
                    ghidraBinaryContext.getSHA256Hash());
            println(message);

            // Write the binary context to the specified output directory
            monitor.setMessage("Writing binary context to file...");
            message = ghidraBinaryContext.toBytesAndWriteToFile(outputDirectoryPath.toString(), 
                    includeRawBinary, includeDecompiledCode, this::println);
            println(message);
            
        } catch (Exception e) {
            println("Error generating binary context: " + e.getMessage());
            e.printStackTrace(getStdErr());
            throw e;
        } finally {
            monitor.setMessage("Binary context generation complete");
        }
    }
}