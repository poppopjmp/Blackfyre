package blackfyre.datatypes.ghidra;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import blackfyre.datatypes.APKHeader;
import blackfyre.protobuf.APKHeaderOuterClass;
import blackfyre.protobuf.BinaryContextOuterClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramInfo;
import ghidra.util.task.TaskMonitor;

public class GhidraAPKBinaryContext extends GhidraBinaryContext {
    
    protected Program theCurrentProgram;
    protected TaskMonitor theMonitor;
    protected APKHeader theAPKHeader;
    
    public GhidraAPKBinaryContext(Program currentProgram, 
                                 TaskMonitor monitor, 
                                 boolean includeDecompiledCode, 
                                 int decompileTimeoutSeconds) {
        super(currentProgram, monitor, includeDecompiledCode, decompileTimeoutSeconds);
        
        theCurrentProgram = currentProgram;
        theMonitor = monitor;
    }
    
    public APKHeader getAPKHeader() {
        return theAPKHeader;
    }
    
    @Override
    protected void initializeHeader() throws Exception {
        // Default values for APK header
        String packageName = "unknown";
        String applicationName = theCurrentProgram.getName();
        String versionName = "1.0";
        int versionCode = 1;
        int minSdkVersion = 1;
        int targetSdkVersion = 1;
        int maxSdkVersion = 0; // 0 means not specified
        
        // Try to get APK metadata from program properties
        ProgramInfo programInfo = theCurrentProgram.getProgramInfo();
        if (programInfo != null) {
            Properties props = programInfo.getProperties();
            if (props != null) {
                if (props.containsKey("PACKAGE_NAME")) {
                    packageName = props.getProperty("PACKAGE_NAME");
                }
                if (props.containsKey("APP_NAME")) {
                    applicationName = props.getProperty("APP_NAME");
                }
                if (props.containsKey("VERSION_NAME")) {
                    versionName = props.getProperty("VERSION_NAME");
                }
                if (props.containsKey("VERSION_CODE")) {
                    try {
                        versionCode = Integer.parseInt(props.getProperty("VERSION_CODE"));
                    } catch (NumberFormatException e) {
                        // Ignore parsing error
                    }
                }
                if (props.containsKey("MIN_SDK")) {
                    try {
                        minSdkVersion = Integer.parseInt(props.getProperty("MIN_SDK"));
                    } catch (NumberFormatException e) {
                        // Ignore parsing error
                    }
                }
                if (props.containsKey("TARGET_SDK")) {
                    try {
                        targetSdkVersion = Integer.parseInt(props.getProperty("TARGET_SDK"));
                    } catch (NumberFormatException e) {
                        // Ignore parsing error
                    }
                }
                if (props.containsKey("MAX_SDK")) {
                    try {
                        maxSdkVersion = Integer.parseInt(props.getProperty("MAX_SDK"));
                    } catch (NumberFormatException e) {
                        // Ignore parsing error
                    }
                }
            }
        }
        
        // Create APK header with basic info
        theAPKHeader = new APKHeader(packageName, applicationName, versionName, versionCode,
                                    minSdkVersion, targetSdkVersion, maxSdkVersion);
        
        // Try to analyze APK file if available
        File apkFile = new File(theCurrentProgram.getExecutablePath());
        if (apkFile.exists() && apkFile.getName().toLowerCase().endsWith(".apk")) {
            try {
                parseAPK(apkFile);
            } catch (Exception e) {
                System.err.println("Error parsing APK file: " + e.getMessage());
            }
        }
    }
    
    private void parseAPK(File apkFile) throws Exception {
        try (ZipFile zip = new ZipFile(apkFile)) {
            // Look for the AndroidManifest.xml
            ZipEntry manifestEntry = zip.getEntry("AndroidManifest.xml");
            if (manifestEntry != null) {
                // In a real implementation, we would need a proper binary XML parser
                // for the AndroidManifest.xml since it's in a binary format
                // For simplicity, we'll check if a decoded version exists
                File decodedManifest = new File(apkFile.getParentFile(), "AndroidManifest.xml");
                if (decodedManifest.exists()) {
                    parseManifest(decodedManifest);
                }
            }
            
            // Check for certificate information
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.startsWith("META-INF/") && 
                    (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    // In a real implementation, we would parse the certificate
                    // For now, just record the signature algorithm based on the extension
                    String sigAlgorithm = name.substring(name.lastIndexOf('.') + 1);
                    theAPKHeader.setCertificateInfo(
                        sigAlgorithm, 
                        "CN=Unknown", 
                        "CN=Unknown", 
                        System.currentTimeMillis() - 86400000, // 1 day ago
                        System.currentTimeMillis() + 31536000000L // 1 year from now
                    );
                    break;
                }
            }
        }
    }
    
    private void parseManifest(File manifestFile) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(manifestFile);
        doc.getDocumentElement().normalize();
        
        // Get package name from manifest
        Element manifestElement = doc.getDocumentElement();
        if (manifestElement.hasAttribute("package")) {
            String packageName = manifestElement.getAttribute("package");
            // Update package name in header
            theAPKHeader = new APKHeader(
                packageName,
                theAPKHeader.getApplicationName(),
                theAPKHeader.getVersionName(),
                theAPKHeader.getVersionCode(),
                theAPKHeader.getMinSdkVersion(),
                theAPKHeader.getTargetSdkVersion(),
                theAPKHeader.getMaxSdkVersion()
            );
        }
        
        // Parse uses-sdk element for SDK versions
        NodeList usesSdkList = doc.getElementsByTagName("uses-sdk");
        if (usesSdkList.getLength() > 0) {
            Element usesSdk = (Element) usesSdkList.item(0);
            if (usesSdk.hasAttribute("android:minSdkVersion")) {
                try {
                    int minSdk = Integer.parseInt(usesSdk.getAttribute("android:minSdkVersion"));
                    theAPKHeader.setMinSdkVersion(minSdk);
                } catch (NumberFormatException e) {
                    // Ignore parsing error
                }
            }
            if (usesSdk.hasAttribute("android:targetSdkVersion")) {
                try {
                    int targetSdk = Integer.parseInt(usesSdk.getAttribute("android:targetSdkVersion"));
                    theAPKHeader.setTargetSdkVersion(targetSdk);
                } catch (NumberFormatException e) {
                    // Ignore parsing error
                }
            }
            if (usesSdk.hasAttribute("android:maxSdkVersion")) {
                try {
                    int maxSdk = Integer.parseInt(usesSdk.getAttribute("android:maxSdkVersion"));
                    theAPKHeader.setMaxSdkVersion(maxSdk);
                } catch (NumberFormatException e) {
                    // Ignore parsing error
                }
            }
        }
        
        // Parse permissions
        NodeList permissionList = doc.getElementsByTagName("uses-permission");
        for (int i = 0; i < permissionList.getLength(); i++) {
            Element permission = (Element) permissionList.item(i);
            if (permission.hasAttribute("android:name")) {
                theAPKHeader.addPermission(permission.getAttribute("android:name"));
            }
        }
        
        // Parse activities
        NodeList activityList = doc.getElementsByTagName("activity");
        for (int i = 0; i < activityList.getLength(); i++) {
            Element activity = (Element) activityList.item(i);
            if (activity.hasAttribute("android:name")) {
                String activityName = activity.getAttribute("android:name");
                theAPKHeader.addActivity(activityName);
                
                // Check if this is the main activity
                NodeList intentFilters = activity.getElementsByTagName("intent-filter");
                for (int j = 0; j < intentFilters.getLength(); j++) {
                    Element intentFilter = (Element) intentFilters.item(j);
                    NodeList categories = intentFilter.getElementsByTagName("category");
                    NodeList actions = intentFilter.getElementsByTagName("action");
                    
                    boolean hasMainAction = false;
                    boolean hasLauncherCategory = false;
                    
                    for (int k = 0; k < actions.getLength(); k++) {
                        Element action = (Element) actions.item(k);
                        if (action.hasAttribute("android:name") && 
                            action.getAttribute("android:name").equals("android.intent.action.MAIN")) {
                            hasMainAction = true;
                            break;
                        }
                    }
                    
                    for (int k = 0; k < categories.getLength(); k++) {
                        Element category = (Element) categories.item(k);
                        if (category.hasAttribute("android:name") && 
                            category.getAttribute("android:name").equals("android.intent.category.LAUNCHER")) {
                            hasLauncherCategory = true;
                            break;
                        }
                    }
                    
                    if (hasMainAction && hasLauncherCategory) {
                        theAPKHeader.setMainActivity(activityName);
                        break;
                    }
                }
            }
        }
        
        // Parse services
        NodeList serviceList = doc.getElementsByTagName("service");
        for (int i = 0; i < serviceList.getLength(); i++) {
            Element service = (Element) serviceList.item(i);
            if (service.hasAttribute("android:name")) {
                theAPKHeader.addService(service.getAttribute("android:name"));
            }
        }
        
        // Parse receivers
        NodeList receiverList = doc.getElementsByTagName("receiver");
        for (int i = 0; i < receiverList.getLength(); i++) {
            Element receiver = (Element) receiverList.item(i);
            if (receiver.hasAttribute("android:name")) {
                theAPKHeader.addReceiver(receiver.getAttribute("android:name"));
            }
        }
        
        // Parse providers
        NodeList providerList = doc.getElementsByTagName("provider");
        for (int i = 0; i < providerList.getLength(); i++) {
            Element provider = (Element) providerList.item(i);
            if (provider.hasAttribute("android:name")) {
                theAPKHeader.addProvider(provider.getAttribute("android:name"));
            }
        }
    }
    
    @Override
    public BinaryContextOuterClass.BinaryContext toPB() throws Exception {
        var binaryContextBuilder = initializeBinaryContextBuilder();
        
        APKHeaderOuterClass.APKHeader apkHeaderPB = theAPKHeader.toPB();
        
        binaryContextBuilder.setApkHeader(apkHeaderPB);
        
        return binaryContextBuilder.build();
    }
}
