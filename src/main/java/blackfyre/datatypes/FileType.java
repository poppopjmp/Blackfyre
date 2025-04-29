package blackfyre.datatypes;

/**
 * Enum representing supported binary file types.
 */
public enum FileType {
    PE32,
    PE64,
    ELF32,
    ELF64,
    MACH_O_32,
    MACH_O_64,
    APK,
    FIRMWARE,
    UNKNOWN
}
