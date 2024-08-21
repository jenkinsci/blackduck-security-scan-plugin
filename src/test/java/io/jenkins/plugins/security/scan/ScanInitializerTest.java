package io.jenkins.plugins.security.scan;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.File;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ScanInitializerTest {
    private SecurityScanner securityScannerMock;
    private TaskListener listenerMock;
    private FilePath workspace;
    private EnvVars envVarsMock;
    private ScanInitializer scanInitializer;

    @BeforeEach
    void setUp() {
        securityScannerMock = Mockito.mock(SecurityScanner.class);
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        envVarsMock = Mockito.mock(EnvVars.class);
        scanInitializer =
                new ScanInitializer(securityScannerMock, workspace, envVarsMock, listenerMock);

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
    public void initializeScannerAirGapSuccessTest() throws PluginExceptionHandler {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);

        int exitCode = scanInitializer.initializeScanner(scanParameters);

        assertEquals(0, exitCode);
    }
}
