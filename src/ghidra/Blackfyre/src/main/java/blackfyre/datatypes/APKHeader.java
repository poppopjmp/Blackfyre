package blackfyre.datatypes;

import java.util.ArrayList;
import java.util.List;

import blackfyre.protobuf.APKHeaderOuterClass;

public class APKHeader {
    private String packageName;           // Package name
    private String applicationName;       // Application name
    private String versionName;           // Version name (string)
    private int versionCode;              // Version code (integer)
    private int minSdkVersion;            // Minimum SDK version
    private int targetSdkVersion;         // Target SDK version
    private int maxSdkVersion;            // Maximum SDK version
    private List<String> permissions;     // List of permissions
    private List<String> activities;      // List of activities
    private List<String> services;        // List of services
    private List<String> receivers;       // List of broadcast receivers
    private List<String> providers;       // List of content providers
    private String mainActivity;          // Main activity class name
    private String signatureAlgorithm;    // Signature algorithm
    private String certificateSubject;    // Certificate subject
    private String certificateIssuer;     // Certificate issuer
    private long certificateValidFrom;    // Certificate valid from timestamp
    private long certificateValidTo;      // Certificate valid to timestamp
    
    public APKHeader(String packageName, String applicationName, String versionName, int versionCode,
                    int minSdkVersion, int targetSdkVersion, int maxSdkVersion) {
        this.packageName = packageName;
        this.applicationName = applicationName;
        this.versionName = versionName;
        this.versionCode = versionCode;
        this.minSdkVersion = minSdkVersion;
        this.targetSdkVersion = targetSdkVersion;
        this.maxSdkVersion = maxSdkVersion;
        this.permissions = new ArrayList<>();
        this.activities = new ArrayList<>();
        this.services = new ArrayList<>();
        this.receivers = new ArrayList<>();
        this.providers = new ArrayList<>();
    }
    
    // Set certificate information
    public void setCertificateInfo(String algorithm, String subject, String issuer, 
                                  long validFrom, long validTo) {
        this.signatureAlgorithm = algorithm;
        this.certificateSubject = subject;
        this.certificateIssuer = issuer;
        this.certificateValidFrom = validFrom;
        this.certificateValidTo = validTo;
    }
    
    // Set main activity
    public void setMainActivity(String mainActivity) {
        this.mainActivity = mainActivity;
    }
    
    // Add permission
    public void addPermission(String permission) {
        this.permissions.add(permission);
    }
    
    // Add activity
    public void addActivity(String activity) {
        this.activities.add(activity);
    }
    
    // Add service
    public void addService(String service) {
        this.services.add(service);
    }
    
    // Add receiver
    public void addReceiver(String receiver) {
        this.receivers.add(receiver);
    }
    
    // Add provider
    public void addProvider(String provider) {
        this.providers.add(provider);
    }
    
    public APKHeaderOuterClass.APKHeader toPB() {
        var builder = APKHeaderOuterClass.APKHeader.newBuilder();
        
        builder.setPackageName(packageName);
        builder.setApplicationName(applicationName);
        builder.setVersionName(versionName);
        builder.setVersionCode(versionCode);
        builder.setMinSdkVersion(minSdkVersion);
        builder.setTargetSdkVersion(targetSdkVersion);
        builder.setMaxSdkVersion(maxSdkVersion);
        
        // Add all permissions
        for (String permission : permissions) {
            builder.addPermissions(permission);
        }
        
        // Add all activities
        for (String activity : activities) {
            builder.addActivities(activity);
        }
        
        // Add all services
        for (String service : services) {
            builder.addServices(service);
        }
        
        // Add all receivers
        for (String receiver : receivers) {
            builder.addReceivers(receiver);
        }
        
        // Add all providers
        for (String provider : providers) {
            builder.addProviders(provider);
        }
        
        // Set main activity if specified
        if (mainActivity != null) {
            builder.setMainActivity(mainActivity);
        }
        
        // Set certificate information if available
        if (signatureAlgorithm != null) {
            builder.setSignatureAlgorithm(signatureAlgorithm);
            builder.setCertificateSubject(certificateSubject);
            builder.setCertificateIssuer(certificateIssuer);
            builder.setCertificateValidFrom(certificateValidFrom);
            builder.setCertificateValidTo(certificateValidTo);
        }
        
        return builder.build();
    }
}
