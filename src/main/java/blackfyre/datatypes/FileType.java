package blackfyre.datatypes;

/**
 * Enum representing supported binary file types
 */
public enum FileType {
    UNKNOWN,
    PE32,
    PE64,
    ELF32,
    ELF64,
    MACHO32,
    MACHO64
}
