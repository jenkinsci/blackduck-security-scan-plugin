package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.report.Sarif;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BlackDuckSCAParametersServiceTest {
    private BlackDuckSCAParametersService blackDuckSCAParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_BLACKDUCKSCA_URL = "https://fake.blackduck.url";
    private final String TEST_BLACKDUCKSCA_TOKEN = "fake-token";
    private final String TEST_PROJECT_DIRECTORY = "DIR/TEST";

    @BeforeEach
    void setUp() {
        blackDuckSCAParametersService = new BlackDuckSCAParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void prepareBlackDuckSCAObjectForBridge_inNonPRContextTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();

        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckScaParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckScaParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY, true);

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckScaParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertNull(blackDuckSCA.getAutomation());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuckSCA.getScan().getFailure().getSeverities());
        assertEquals(blackDuckSCA.isWaitForScan(), true);
    }

    @Test
    void prepareBlackDuckSCAObjectForBridge_inNonPRContext_withSarifParametersTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();

        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckScaParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckScaParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY, true);
        blackDuckScaParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        blackDuckScaParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY, true);

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckScaParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertNull(blackDuckSCA.getAutomation());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuckSCA.getScan().getFailure().getSeverities());
        assertTrue(blackDuckSCA.getReports().getSarif().getCreate());
        assertEquals(
                "/path/to/sarif/file",
                blackDuckSCA.getReports().getSarif().getFile().getPath());
        assertEquals(
                Arrays.asList("HIGH", "MEDIUM", "LOW"),
                blackDuckSCA.getReports().getSarif().getSeverities());
        assertTrue(blackDuckSCA.getReports().getSarif().getGroupSCAIssues());
        assertEquals(blackDuckSCA.isWaitForScan(), true);
    }

    @Test
    void prepareBlackDuckSCAObjectForBridge_inPRContextTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();

        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckScaParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckScaParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertEquals(true, blackDuckSCA.getAutomation().getPrComment());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuckSCA.getScan().getFailure().getSeverities());
    }

    @Test
    void validateBlackDuckParametersForValidParametersTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);

        assertTrue(blackDuckSCAParametersService.hasAllMandatoryBlackduckSCAParams(blackDuckScaParametersMap));
    }

    @Test
    void validateBlackDuckParametersForMissingParametersTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);

        assertFalse(blackDuckSCAParametersService.hasAllMandatoryBlackduckSCAParams(blackDuckScaParametersMap));
    }

    @Test
    void validateBlackDuckParametersForNullAndEmptyTest() {
        assertFalse(blackDuckSCAParametersService.hasAllMandatoryBlackduckSCAParams(null));

        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "");
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);

        assertFalse(blackDuckSCAParametersService.hasAllMandatoryBlackduckSCAParams(blackDuckScaParametersMap));
    }

    @Test
    void prepareBlackDuckSCAObjectForBridge_projectDirectoryTest() {
        Map<String, Object> blackDuckScaParametersMap = new HashMap<>();

        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckScaParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckScaParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckScaParametersMap);
        Project project = blackDuckSCAParametersService.prepareProjectObjectForBridge(blackDuckScaParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
    }

    @Test
    public void prepareBlackduckSarifObjectTest() {
        Map<String, Object> sarifParameters = new HashMap<>();

        sarifParameters.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY, true);
        sarifParameters.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        sarifParameters.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        sarifParameters.put(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);

        Sarif sarifObject = blackDuckSCAParametersService.prepareSarifObject(sarifParameters);

        assertNotNull(sarifObject);
        assertTrue(sarifObject.getCreate());
        assertEquals("/path/to/sarif/file", sarifObject.getFile().getPath());
        assertEquals(Arrays.asList("HIGH", "MEDIUM", "LOW"), sarifObject.getSeverities());
        assertTrue(sarifObject.getGroupSCAIssues());
    }
}
