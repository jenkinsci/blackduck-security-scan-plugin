package io.jenkins.plugins.security.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

public class ScanInitializerTest {
    private ScanInitializer scanInitializer;
    private ScanInitializer scanInitializerMock;

    @BeforeEach
    void setUp() {
        SecurityScanner securityScannerMock = Mockito.mock(SecurityScanner.class);
        FilePath workspace = new FilePath(new File(System.getProperty("user.home")));
        TaskListener listenerMock = Mockito.mock(TaskListener.class);
        EnvVars envVarsMock = Mockito.mock(EnvVars.class);
        scanInitializerMock = mock(ScanInitializer.class);
        scanInitializer = new ScanInitializer(securityScannerMock, workspace, envVarsMock, listenerMock);

        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    public void initializeScannerValidParametersTest() throws PluginExceptionHandler {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");

        int exitCode = scanInitializer.initializeScanner(scanParameters);

        assertEquals(0, exitCode);
    }

    @Test
    public void initializeScannerInvalidParametersTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");

        assertThrows(PluginExceptionHandler.class, () -> scanInitializer.initializeScanner(scanParameters));
    }

    @Test
    public void initializeScannerAirGapFailureTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);
        scanParameters.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/path/to/bridge");

        assertThrows(PluginExceptionHandler.class, () -> scanInitializer.initializeScanner(scanParameters));
    }

    @Test
    public void initializeScannerSSLConfigFailureTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_SSL_TRUSTALL_KEY, true);
        scanParameters.put(ApplicationConstants.NETWORK_SSL_CERT_FILE_KEY, "/path/to/cert.pem");

        assertThrows(PluginExceptionHandler.class, () -> scanInitializer.initializeScanner(scanParameters));
    }

    @Test
    public void initializeScannerSSLConfigSuccessTest() throws PluginExceptionHandler {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_SSL_TRUSTALL_KEY, true);

        int exitCode = scanInitializer.initializeScanner(scanParameters);

        assertEquals(0, exitCode);
    }

    @Test
    public void initializeScannerAirGapSuccessTest(@TempDir Path bridgeInstallDir)
            throws PluginExceptionHandler, IOException {
        // Air-gap mode never downloads Bridge CLI, so it has to be installed already. Use an isolated stub
        // install instead of relying on a Bridge CLI left in the shared user.home by other tests.
        // The plugin looks for it in "<install dir>/bridge-cli-bundle-<platform>", where the platform depends on the
        // OS/arch, so a stub is created for every platform.
        for (String platform : Arrays.asList(
                ApplicationConstants.PLATFORM_LINUX,
                ApplicationConstants.PLATFORM_LINUX_ARM,
                ApplicationConstants.PLATFORM_WINDOWS,
                ApplicationConstants.PLATFORM_MACOSX,
                ApplicationConstants.PLATFORM_MAC_ARM)) {
            Path platformDir = Files.createDirectories(
                    bridgeInstallDir.resolve(ApplicationConstants.DEFAULT_DIRECTORY_NAME + "-" + platform));
            Files.createFile(platformDir.resolve(ApplicationConstants.BRIDGE_CLI_EXECUTABLE));
            Files.write(
                    platformDir.resolve(ApplicationConstants.VERSION_FILE),
                    "bridge-cli-bundle: 3.5.0\n".getBytes(StandardCharsets.UTF_8));
        }

        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);
        scanParameters.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, bridgeInstallDir.toString());

        int exitCode = scanInitializer.initializeScanner(scanParameters);

        assertEquals(0, exitCode);
    }

    @Test
    public void testLogMessagesForParameters_basic() {
        Map<String, Object> scanParameters = new HashMap<>();
        Set<String> securityProducts = Collections.emptySet();

        doNothing().when(scanInitializerMock).logMessagesForParameters(isA(Map.class), isA(Set.class));

        scanInitializerMock.logMessagesForParameters(scanParameters, securityProducts);

        verify(scanInitializerMock, times(1)).logMessagesForParameters(scanParameters, securityProducts);
    }
}
