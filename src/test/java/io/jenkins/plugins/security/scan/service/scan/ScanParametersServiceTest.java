package io.jenkins.plugins.security.scan.service.scan;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class ScanParametersServiceTest {
    private ScanParametersService scanParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);

    @BeforeEach
    void setUp() {
        scanParametersService = new ScanParametersService(listenerMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void performScanParameterValidation_successForBlackDuckTest() throws PluginExceptionHandler {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "blackducksca");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "fake-token");

        assertTrue(scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_failureForBlackDuckTest() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "blackducksca");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");

        assertThrows(PluginExceptionHandler.class,
                () -> scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_successForCoverityTest() throws PluginExceptionHandler {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "coverity");
        parameters.put(ApplicationConstants.COVERITY_URL_KEY, "https://fake.coverity.url");
        parameters.put(ApplicationConstants.COVERITY_USER_KEY, "fake-user");
        parameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, "fake-passphrase");
        parameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-project");
        parameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-stream");

        assertTrue(scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_failureForCoverityTest() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "coverity");
        parameters.put(ApplicationConstants.COVERITY_URL_KEY, "https://fake.coverity.url");
        parameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-project");
        parameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-stream");

        assertThrows(PluginExceptionHandler.class,
                () -> scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_successForPolarisTest() throws PluginExceptionHandler {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "polaris");
        parameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, "https://fake.polaris.url");
        parameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, "fake-token");
        parameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, "fake-application");
        parameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SCA,SAST");
        parameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project");
        parameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "fake-branch");

        assertTrue(scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_failureForPolarisTest() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "polaris");
        parameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, "https://fake.polaris.url");
        parameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, "fake-application");
        parameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project");
        parameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "fake-branch");

        assertThrows(PluginExceptionHandler.class,
                () -> scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_successForBlackDuckAndPolarisTest() throws PluginExceptionHandler {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "blackduck, polaris");

        parameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "fake-token");

        parameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, "https://fake.polaris.url");
        parameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, "fake-token");
        parameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, "test-application");
        parameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "test-project");
        parameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SCA, SAST");
        parameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");

        assertTrue(scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_failureForBlackDuckAndPolarisTest() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "blackduck, polaris");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake.blackduck.url");
        parameters.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "fake-token");

        assertThrows(
                PluginExceptionHandler.class,
                () -> scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_successForSrmTest() throws PluginExceptionHandler {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "srm");
        parameters.put(ApplicationConstants.SRM_URL_KEY, "https://fake.srm.url");
        parameters.put(ApplicationConstants.SRM_APIKEY_KEY, "fake-token");
        parameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, "SCA");
        parameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, "test-project");
        parameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, "fake-id");
        parameters.put(ApplicationConstants.SRM_BRANCH_NAME_KEY, "test");
        parameters.put(ApplicationConstants.SRM_BRANCH_PARENT_KEY, "main");

        assertTrue(scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    void performScanParameterValidation_failureForSrmTest() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(ApplicationConstants.PRODUCT_KEY, "srm");
        parameters.put(ApplicationConstants.SRM_URL_KEY, "https://fake.srm.url");

        assertThrows(
                PluginExceptionHandler.class,
                () -> scanParametersService.performScanParameterValidation(parameters, envVarsMock));
    }

    @Test
    public void getSynopsysSecurityProducts_singleProductTest() {
        Map<String, Object> scanParametersWithSinglePlatform = new HashMap<>();
        scanParametersWithSinglePlatform.put(ApplicationConstants.PRODUCT_KEY, "blackducksca");

        Set<String> singlePlatform = scanParametersService.getSecurityProducts(scanParametersWithSinglePlatform);

        assertEquals(1, singlePlatform.size());
    }

    @Test
    public void getSynopsysSecurityProducts_multipleProductTest() {
        Map<String, Object> scanParametersWithMultiplePlatforms = new HashMap<>();
        scanParametersWithMultiplePlatforms.put(ApplicationConstants.PRODUCT_KEY, "blackducksca, polaris");

        Set<String> multiplePlatforms = scanParametersService.getSecurityProducts(scanParametersWithMultiplePlatforms);

        assertEquals(2, multiplePlatforms.size());
    }
}
