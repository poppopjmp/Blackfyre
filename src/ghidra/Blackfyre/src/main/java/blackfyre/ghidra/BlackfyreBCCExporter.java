package blackfyre.ghidra;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import blackfyre.datatypes.ArchWordSize;
import blackfyre.datatypes.Endness;
import blackfyre.datatypes.FileType;
import blackfyre.datatypes.MessageType;
import blackfyre.datatypes.ProcessorType;
import blackfyre.datatypes.ghidra.GhidraFunctionContext;
import blackfyre.datatypes.protobuf.BinaryContextOuterClass;
import blackfyre.datatypes.protobuf.FunctionContextOuterClass;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class BlackfyreBCCExporter {
    
    private Program theCurrentProgram;
    private TaskMonitor theMonitor;
    private String theBCCVersion = "1.0.1";
    
    public BlackfyreBCCExporter(Program currentProgram, TaskMonitor monitor) {
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public String calculateSHA256() {
        try {
            File file = new File(theCurrentProgram.getExecutablePath());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(file);
            
            byte[] byteArray = new byte[8192];
            int bytesCount = 0;
            
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
            
            fis.close();
            
            byte[] bytes = digest.digest();
            
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            return sb.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            Msg.error(this, "Error calculating SHA-256: " + e.getMessage());
            return "";
        }
    }
    
    public ProcessorType getProcessorType() {
        String processor = theCurrentProgram.getLanguage().getProcessor().toString().toLowerCase();
        
        if (processor.contains("x86")) {
            if (theCurrentProgram.getLanguage().getLanguageDescription().getSize() == 64) {
                return ProcessorType.x86_64;
            } else {
                return ProcessorType.x86;
            }
        } else if (processor.contains("arm")) {
            if (theCurrentProgram.getLanguage().getLanguageDescription().getSize() == 64) {
                return ProcessorType.AARCH64;
            } else {
                return ProcessorType.ARM;
            }
        } else if (processor.contains("mips")) {
            return ProcessorType.MIPS;
        } else if (processor.contains("ppc") || processor.contains("powerpc")) {
            return ProcessorType.PPC;
        }
        
        return ProcessorType.UNKNOWN;
    }
    
    public FileType getFileType() {
        String format = theCurrentProgram.getExecutableFormat();
        boolean is64Bit = theCurrentProgram.getLanguage().getLanguageDescription().getSize() == 64;
        
        if (format.contains("PE")) {
            return is64Bit ? FileType.PE64 : FileType.PE32;
        } else if (format.contains("ELF")) {
            return is64Bit ? FileType.ELF64 : FileType.ELF32;
        } else if (format.contains("Mac")) {
            return is64Bit ? FileType.MACH_O_64 : FileType.MACH_O_32;
        }
        
        return FileType.UNKNOWN;
    }
    
    public Endness getEndness() {
        boolean isBigEndian = theCurrentProgram.getLanguage().isBigEndian();
        return isBigEndian ? Endness.BIG_ENDIAN : Endness.LITTLE_ENDIAN;
    }
    
    public ArchWordSize getWordSize() {
        int size = theCurrentProgram.getLanguage().getLanguageDescription().getSize();
        return size == 64 ? ArchWordSize.BITS_64 : ArchWordSize.BITS_32;
    }
    
    public HashMap<Long, String> collectStrings() {
        HashMap<Long, String> stringRefs = new HashMap<>();
        
        // Iterate through memory sections looking for defined data that is a string
        var memory = theCurrentProgram.getMemory();
        var listing = theCurrentProgram.getListing();
        
        for (var block : memory.getBlocks()) {
            var addrSet = block.getAddressRange();
            var dataIterator = listing.getDefinedData(addrSet, true);
            
            while (dataIterator.hasNext() && !theMonitor.isCancelled()) {
                var data = dataIterator.next();
                if (data.hasStringValue()) {
                    stringRefs.put(data.getAddress().getOffset(), data.getDefaultValueRepresentation());
                }
            }
        }
        
        return stringRefs;
    }
    
    public List<HashMap<String, Object>> collectImports() {
        List<HashMap<String, Object>> imports = new ArrayList<>();
        
        var externalManager = theCurrentProgram.getExternalManager();
        var symbolTable = theCurrentProgram.getSymbolTable();
        
        for (var library : externalManager.getExternalLibraryNames()) {
            var symbols = symbolTable.getExternalSymbols(library);
            
            for (var symbol : symbols) {
                var importInfo = new HashMap<String, Object>();
                importInfo.put("name", symbol.getName());
                importInfo.put("library", library);
                importInfo.put("address", symbol.getAddress().getOffset());
                
                imports.add(importInfo);
            }
        }
        
        return imports;
    }
    
    public List<HashMap<String, Object>> collectExports() {
        List<HashMap<String, Object>> exports = new ArrayList<>();
        
        var symbolTable = theCurrentProgram.getSymbolTable();
        var entryPoints = symbolTable.getExternalEntryPointSymbols();
        
        for (var symbol : entryPoints) {
            var exportInfo = new HashMap<String, Object>();
            exportInfo.put("name", symbol.getName());
            exportInfo.put("address", symbol.getAddress().getOffset());
            
            exports.add(exportInfo);
        }
        
        return exports;
    }
    
    public List<HashMap<String, Object>> collectSections() {
        List<HashMap<String, Object>> sections = new ArrayList<>();
        
        var memory = theCurrentProgram.getMemory();
        
        for (var block : memory.getBlocks()) {
            var sectionInfo = new HashMap<String, Object>();
            sectionInfo.put("name", block.getName());
            sectionInfo.put("start_address", block.getStart().getOffset());
            sectionInfo.put("end_address", block.getEnd().getOffset());
            sectionInfo.put("readable", block.isRead());
            sectionInfo.put("writable", block.isWrite());
            sectionInfo.put("executable", block.isExecute());
            
            sections.add(sectionInfo);
        }
        
        return sections;
    }
    
    public List<GhidraFunctionContext> collectFunctions(boolean includeDecompiledCode, int decompileTimeout) {
        List<GhidraFunctionContext> functions = new ArrayList<>();
        
        var functionManager = theCurrentProgram.getFunctionManager();
        var procType = getProcessorType();
        
        for (var function : functionManager.getFunctions(true)) {
            if (theMonitor.isCancelled()) {
                break;
            }
            
            var funcContext = new GhidraFunctionContext(
                theCurrentProgram,
                function,
                theMonitor,
                procType,
                includeDecompiledCode,
                decompileTimeout
            );
            
            // Initialize and add if successful
            if (funcContext.initialize()) {
                functions.add(funcContext);
            }
        }
        
        return functions;
    }
    
    public boolean exportToBCC(String outputPath, boolean includeRawBinary, boolean extendedAnalysis) {
        try {
            Msg.info(this, "Starting BCC export...");
            
            // Calculate binary hash
            String sha256 = calculateSHA256();
            Msg.info(this, "SHA256: " + sha256);
            
            // Get binary name
            String binaryName = new File(theCurrentProgram.getExecutablePath()).getName();
            Msg.info(this, "Binary Name: " + binaryName);
            
            // Collect data
            Msg.info(this, "Collecting strings...");
            var strings = collectStrings();
            Msg.info(this, "Found " + strings.size() + " strings");
            
            Msg.info(this, "Collecting imports...");
            var imports = collectImports();
            Msg.info(this, "Found " + imports.size() + " imports");
            
            Msg.info(this, "Collecting exports...");
            var exports = collectExports();
            Msg.info(this, "Found " + exports.size() + " exports");
            
            Msg.info(this, "Collecting sections...");
            var sections = collectSections();
            Msg.info(this, "Found " + sections.size() + " sections");
            
            Msg.info(this, "Collecting functions...");
            var functions = collectFunctions(extendedAnalysis, extendedAnalysis ? 30 : 0);
            Msg.info(this, "Found " + functions.size() + " functions");
            
            // Build binary context protobuf
            Msg.info(this, "Building BCC data...");
            var binaryContextBuilder = BinaryContextOuterClass.BinaryContext.newBuilder();
            
            // Add metadata
            binaryContextBuilder.getMetadataBuilder()
                .setBccVersion(theBCCVersion)
                .setBinaryName(binaryName)
                .setSha256(sha256)
                .setProcessorType(getProcessorType().getNumVal())
                .setFileType(getFileType().getNumVal())
                .setEndness(getEndness().getNumVal())
                .setWordSize(getWordSize().getNumVal())
                .setToolName("Ghidra")
                .setToolVersion(theCurrentProgram.getCompiler());
            
            // Add entry point if available
            var entryPoints = theCurrentProgram.getSymbolTable().getExternalEntryPointSymbols();
            if (entryPoints.hasNext()) {
                binaryContextBuilder.getMetadataBuilder()
                    .setEntryPoint(entryPoints.next().getAddress().getOffset());
            }
            
            // Add strings
            for (var entry : strings.entrySet()) {
                binaryContextBuilder.addStringsBuilder()
                    .setAddress(entry.getKey())
                    .setValue(entry.getValue());
            }
            
            // Add imports
            for (var imp : imports) {
                binaryContextBuilder.addImportsBuilder()
                    .setName((String)imp.get("name"))
                    .setLibrary((String)imp.get("library"))
                    .setAddress((Long)imp.get("address"));
            }
            
            // Add exports
            for (var exp : exports) {
                binaryContextBuilder.addExportsBuilder()
                    .setName((String)exp.get("name"))
                    .setAddress((Long)exp.get("address"));
            }
            
            // Add sections
            for (var section : sections) {
                int permissions = 0;
                if ((Boolean)section.get("readable")) permissions |= 1;
                if ((Boolean)section.get("writable")) permissions |= 2;
                if ((Boolean)section.get("executable")) permissions |= 4;
                
                binaryContextBuilder.addSectionsBuilder()
                    .setName((String)section.get("name"))
                    .setStartAddress((Long)section.get("start_address"))
                    .setEndAddress((Long)section.get("end_address"))
                    .setPermissions(permissions);
            }
            
            // Add function references
            for (var function : functions) {
                binaryContextBuilder.addFunctionsBuilder()
                    .setName(function.getThefunctionName())
                    .setAddress(function.getTheStartAddress())
                    .setSize(function.getTheEndAddress() - function.getTheStartAddress());
            }
            
            // Write to file
            Msg.info(this, "Writing to file: " + outputPath);
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                // Write binary context
                byte[] bcBytes = binaryContextBuilder.build().toByteArray();
                fos.write(ByteBuffer.allocate(8)
                    .putInt(MessageType.BINARY_CONTEXT_MSG.getNumVal())
                    .putInt(bcBytes.length)
                    .array());
                fos.write(bcBytes);
                
                // Write function contexts
                for (var function : functions) {
                    if (theMonitor.isCancelled()) {
                        return false;
                    }
                    
                    byte[] fcBytes = function.toPB().toByteArray();
                    fos.write(ByteBuffer.allocate(8)
                        .putInt(MessageType.FUNCTION_CONTEXT_MSG.getNumVal())
                        .putInt(fcBytes.length)
                        .array());
                    fos.write(fcBytes);
                }
                
                // Include raw binary if requested
                if (includeRawBinary) {
                    File binaryFile = new File(theCurrentProgram.getExecutablePath());
                    byte[] binaryData = new byte[(int)binaryFile.length()];
                    
                    try (FileInputStream fis = new FileInputStream(binaryFile)) {
                        fis.read(binaryData);
                    }
                    
                    fos.write(ByteBuffer.allocate(8)
                        .putInt(MessageType.RAW_BINARY_MSG.getNumVal())
                        .putInt(binaryData.length)
                        .array());
                    fos.write(binaryData);
                }
                
                // Add SHA-256 validation
                byte[] fileContent = new byte[(int)new File(outputPath).length()];
                try (FileInputStream fis = new FileInputStream(outputPath)) {
                    fis.read(fileContent);
                }
                
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest(fileContent);
                
                fos.write(ByteBuffer.allocate(8)
                    .putInt(MessageType.SHA256_VALIDATION_MSG.getNumVal())
                    .putInt(hashBytes.length)
                    .array());
                fos.write(hashBytes);
            }
            
            Msg.info(this, "Export completed successfully");
            return true;
            
        } catch (Exception e) {
            Msg.error(this, "Error exporting to BCC: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean importBCC(String inputPath) {
        try {
            Msg.info(this, "Importing BCC file: " + inputPath);
            
            // Open and read file
            File bccFile = new File(inputPath);
            byte[] fileContent = new byte[(int)bccFile.length()];
            
            try (FileInputStream fis = new FileInputStream(bccFile)) {
                fis.read(fileContent);
            }
            
            // Parse TLV structure
            int offset = 0;
            BinaryContextOuterClass.BinaryContext binaryContext = null;
            List<FunctionContextOuterClass.FunctionContext> functionContexts = new ArrayList<>();
            
            while (offset < fileContent.length - 8) {
                // Parse header
                ByteBuffer headerBuffer = ByteBuffer.wrap(fileContent, offset, 8);
                int msgType = headerBuffer.getInt();
                int msgLen = headerBuffer.getInt();
                offset += 8;
                
                // Get message data
                if (offset + msgLen > fileContent.length) {
                    Msg.error(this, "Invalid message length at offset " + (offset - 8));
                    break;
                }
                
                byte[] msgData = new byte[msgLen];
                System.arraycopy(fileContent, offset, msgData, 0, msgLen);
                offset += msgLen;
                
                // Process by type
                if (msgType == MessageType.BINARY_CONTEXT_MSG.getNumVal()) {
                    binaryContext = BinaryContextOuterClass.BinaryContext.parseFrom(msgData);
                    
                    // Verify binary hash
                    String currentHash = calculateSHA256();
                    if (!binaryContext.getMetadata().getSha256().equals(currentHash)) {
                        Msg.warn(this, "BCC file is for a different binary");
                        Msg.warn(this, "BCC SHA256: " + binaryContext.getMetadata().getSha256());
                        Msg.warn(this, "Current binary SHA256: " + currentHash);
                    }
                    
                    Msg.info(this, "Found binary context: " + binaryContext.getMetadata().getBinaryName());
                    Msg.info(this, "BCC version: " + binaryContext.getMetadata().getBccVersion());
                    
                } else if (msgType == MessageType.FUNCTION_CONTEXT_MSG.getNumVal()) {
                    var functionContext = FunctionContextOuterClass.FunctionContext.parseFrom(msgData);
                    functionContexts.add(functionContext);
                }
            }
            
            if (binaryContext == null) {
                Msg.error(this, "No valid binary context found in file");
                return false;
            }
            
            Msg.info(this, "Found " + functionContexts.size() + " function contexts");
            
            // Apply data to the program
            int appliedComments = 0;
            int appliedNames = 0;
            int appliedTypes = 0;
            
            // Apply strings
            for (var stringRef : binaryContext.getStringsList()) {
                Address addr = theCurrentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(stringRef.getAddress()));
                if (theCurrentProgram.getMemory().contains(addr)) {
                    theCurrentProgram.getListing().setComment(addr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, "String: " + stringRef.getValue());
                    appliedComments++;
                }
            }
            
            // Apply function data
            for (var funcContext : functionContexts) {
                Address funcAddr = theCurrentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(funcContext.getStartAddress()));
                Function func = theCurrentProgram.getFunctionManager().getFunctionAt(funcAddr);
                
                if (func == null) {
                    continue;
                }
                
                // Apply function name if it's more meaningful
                String currentName = func.getName();
                String importedName = funcContext.getName();
                
                if (importedName != null && !importedName.isEmpty() && 
                    !importedName.startsWith("FUN_") && currentName.startsWith("FUN_")) {
                    func.setName(importedName, ghidra.program.model.symbol.SourceType.IMPORTED);
                    appliedNames++;
                }
                
                // Apply function comment
                func.setComment("Imported from BCC - " + importedName);
                
                // Add decompiled code as comment if available
                if (funcContext.getDecompiledCode() != null && !funcContext.getDecompiledCode().isEmpty()) {
                    func.setComment(func.getComment() + "\n\nDecompiled Code:\n" + 
                                    funcContext.getDecompiledCode().substring(0, Math.min(500, funcContext.getDecompiledCode().length())) + "...");
                    appliedComments++;
                }
                
                // Apply basic block comments
                for (var bb : funcContext.getBasicBlockContextListList()) {
                    Address bbAddr = theCurrentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(bb.getStartAddress()));
                    theCurrentProgram.getListing().setComment(bbAddr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, 
                                                              "Block from " + importedName);
                    appliedComments++;
                }
            }
            
            Msg.info(this, "Applied data from BCC:");
            Msg.info(this, "- " + appliedComments + " comments");
            Msg.info(this, "- " + appliedNames + " function names");
            Msg.info(this, "- " + appliedTypes + " types");
            
            return true;
            
        } catch (Exception e) {
            Msg.error(this, "Error importing BCC: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
