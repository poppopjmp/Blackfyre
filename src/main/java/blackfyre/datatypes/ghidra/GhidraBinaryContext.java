package blackfyre.datatypes.ghidra;

import blackfyre.datatypes.FileType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Base class representing a binary context in Ghidra
 */
public class GhidraBinaryContext {
    protected Program program;
    protected TaskMonitor monitor;
    protected boolean includeDecompiledCode;
    protected int decompileTimeoutSeconds;

    /**
     * Constructor for GhidraBinaryContext
     *
     * @param program The Ghidra program object
     * @param monitor The task monitor for tracking progress
     * @param includeDecompiledCode Whether to include decompiled code
     * @param decompileTimeoutSeconds Timeout for decompilation operations
     */
    public GhidraBinaryContext(Program program, TaskMonitor monitor, boolean includeDecompiledCode, int decompileTimeoutSeconds) {
        this.program = program;
        this.monitor = monitor;
        this.includeDecompiledCode = includeDecompiledCode;
        this.decompileTimeoutSeconds = decompileTimeoutSeconds;
    }

    /**
     * Determines the file type from the Ghidra program
     *
     * @param program The Ghidra program object
     * @return The detected file type
     */
    public static FileType getFileTypeFromGhidra(Program program) {
        if (program == null) {
            return FileType.UNKNOWN;
        }

        // Check for PE format
        if (program.getOptions("Program Information").contains(NTHeader.PROGRAM_INFO)) {
            boolean is64Bit = program.getLanguage().getLanguageDescription().getSize() == 64;
            return is64Bit ? FileType.PE64 : FileType.PE32;
        }
        
        // Check for ELF format
        if (program.getOptions("Program Information").contains(ElfHeader.PROGRAM_INFO)) {
            boolean is64Bit = program.getLanguage().getLanguageDescription().getSize() == 64;
            return is64Bit ? FileType.ELF64 : FileType.ELF32;
        }
        
        // Check for Mach-O format
        if (program.getOptions("Program Information").contains(MachHeader.PROGRAM_INFO)) {
            boolean is64Bit = program.getLanguage().getLanguageDescription().getSize() == 64;
            return is64Bit ? FileType.MACH_O_64 : FileType.MACH_O_32;
        }

        // Further checks could be added for other formats like APK, FIRMWARE, etc.
        
        return FileType.UNKNOWN;
    }
}
