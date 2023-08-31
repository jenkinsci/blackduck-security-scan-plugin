package com.synopsys.integration.jenkins.scan.service.scan.polaris;

import com.synopsys.integration.jenkins.scan.global.ApplicationConstants;
import com.synopsys.integration.jenkins.scan.global.enums.ScanType;
import com.synopsys.integration.jenkins.scan.input.polaris.Polaris;
import hudson.model.TaskListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

public class PolarisParametersServiceTest {
    private PolarisParametersService polarisParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final String TEST_POLARIS_SERVER_URL = "https://fake.polaris-server.url";
    private final String TEST_POLARIS_ACCESS_TOKEN = "fakePolarisAccessToken";
    private final String TEST_APPLICATION_NAME = "fake-polaris-application-name";
    private final String TEST_POLARIS_ASSESSMENT_TYPES = "SCA, SAST";

    @BeforeEach
    void setUp() {
        polarisParametersService = new PolarisParametersService(listenerMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void getScanTypeTest() {
        assertNotEquals(ScanType.BLACKDUCK, polarisParametersService.getScanType());
        assertEquals(ScanType.POLARIS, polarisParametersService.getScanType());
        assertNotEquals(ScanType.COVERITY, polarisParametersService.getScanType());
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();
        
        assertFalse(polarisParametersService.isValidScanParameters(polarisParameters));

        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);

        assertFalse(polarisParametersService.isValidScanParameters(polarisParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_ASSESSMENT_TYPES_KEY, TEST_POLARIS_ASSESSMENT_TYPES);

        assertTrue(polarisParametersService.isValidScanParameters(polarisParameters));
    }

    @Test
    void prepareScanInputForBridgeTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.BRIDGE_POLARIS_ASSESSMENT_TYPES_KEY, "SAST");

        Polaris polaris = polarisParametersService.prepareScanInputForBridge(polarisParameters);
        
        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getProjectName().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), Arrays.asList("SAST"));
    }
}