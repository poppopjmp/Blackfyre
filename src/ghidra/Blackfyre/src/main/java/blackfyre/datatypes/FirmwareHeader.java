package blackfyre.datatypes;

import blackfyre.protobuf.FirmwareHeaderOuterClass;

public class FirmwareHeader {
    private String firmwareType;      // Type of firmware (e.g., router, IoT device)
    private String deviceModel;       // Target device model
    private String firmwareVersion;   // Version of the firmware
    private long baseAddress;         // Base address for loading
    private long entryPoint;          // Entry point address
    private long textSectionAddress;  // Address of text section
    private long textSectionSize;     // Size of text section
    private long dataSectionAddress;  // Address of data section
    private long dataSectionSize;     // Size of data section
    private long bssSectionAddress;   // Address of BSS section
    private long bssSectionSize;      // Size of BSS section
    private String architecture;      // Target architecture
    private long buildTimestamp;      // Firmware build timestamp
    
    public FirmwareHeader(String firmwareType, String deviceModel, String firmwareVersion,
                         long baseAddress, long entryPoint, 
                         long textSectionAddress, long textSectionSize,
                         long dataSectionAddress, long dataSectionSize,
                         long bssSectionAddress, long bssSectionSize,
                         String architecture, long buildTimestamp) {
        this.firmwareType = firmwareType;
        this.deviceModel = deviceModel;
        this.firmwareVersion = firmwareVersion;
        this.baseAddress = baseAddress;
        this.entryPoint = entryPoint;
        this.textSectionAddress = textSectionAddress;
        this.textSectionSize = textSectionSize;
        this.dataSectionAddress = dataSectionAddress;
        this.dataSectionSize = dataSectionSize;
        this.bssSectionAddress = bssSectionAddress;
        this.bssSectionSize = bssSectionSize;
        this.architecture = architecture;
        this.buildTimestamp = buildTimestamp;
    }
    
    public FirmwareHeaderOuterClass.FirmwareHeader toPB() {
        var builder = FirmwareHeaderOuterClass.FirmwareHeader.newBuilder();
        
        builder.setFirmwareType(firmwareType);
        builder.setDeviceModel(deviceModel);
        builder.setFirmwareVersion(firmwareVersion);
        builder.setBaseAddress(baseAddress);
        builder.setEntryPoint(entryPoint);
        builder.setTextSectionAddress(textSectionAddress);
        builder.setTextSectionSize(textSectionSize);
        builder.setDataSectionAddress(dataSectionAddress);
        builder.setDataSectionSize(dataSectionSize);
        builder.setBssSectionAddress(bssSectionAddress);
        builder.setBssSectionSize(bssSectionSize);
        builder.setArchitecture(architecture);
        builder.setBuildTimestamp(buildTimestamp);
        
        return builder.build();
    }
}
