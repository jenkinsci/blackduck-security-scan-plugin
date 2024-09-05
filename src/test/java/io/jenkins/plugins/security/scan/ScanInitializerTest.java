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
import java.io.PrintStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
    public void initializeScannerAirGapSuccessTest() throws PluginExceptionHandler {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.PRODUCT_KEY, "BLACKDUCKSCA");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        scanParameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "MDJDSROSVC56FAKEKEY");
        scanParameters.put(ApplicationConstants.NETWORK_AIRGAP_KEY, true);

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
