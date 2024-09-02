package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.blackduck.BlackDuck;
import io.jenkins.plugins.security.scan.input.project.Project;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class BlackDuckSCAParametersServiceTest {
    private BlackDuckSCAParametersService blackDuckSCAParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_BLACKDUCKSCA_URL = "https://fake.blackduck.url";
    private final String TEST_BLACKDUCKSCA_TOKEN = "MDJDSROSVC56FAKEKEY";
    private final String TEST_DETECT_INSTALL_DIRECTORY_PATH = "/path/to/blackduck/directory";
    private final String TEST_PROJECT_DIRECTORY = "DIR/TEST";
    private final String TEST_BLACKDUCKSCA_ARGS = "--detect.diagnostic=true";
    private final String TEST_BLACKDUCKSCA_CONFIG_FILE_PATH = "DIR/CONFIG/application.properties";

    @BeforeEach
    void setUp() {
        blackDuckSCAParametersService = new BlackDuckSCAParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void createBlackDuckObjectForNonPRContextTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckParametersMap.put(
                ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY, TEST_DETECT_INSTALL_DIRECTORY_PATH);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);

        BlackDuck blackDuck = blackDuckSCAParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuck.getToken());
        assertEquals(
                TEST_DETECT_INSTALL_DIRECTORY_PATH, blackDuck.getInstall().getDirectory());
        assertNull(blackDuck.getAutomation());
        assertEquals(true, blackDuck.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuck.getScan().getFailure().getSeverities());
    }

    @Test
    void createBlackDuckObjectForPRContextTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckParametersMap.put(
                ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY, TEST_DETECT_INSTALL_DIRECTORY_PATH);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        BlackDuck blackDuck = blackDuckSCAParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuck.getToken());
        assertEquals(
                TEST_DETECT_INSTALL_DIRECTORY_PATH, blackDuck.getInstall().getDirectory());
        assertEquals(true, blackDuck.getAutomation().getPrComment());
        assertEquals(true, blackDuck.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuck.getScan().getFailure().getSeverities());
    }

    @Test
    void validateBlackDuckParametersForValidParametersTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);

        assertTrue(blackDuckSCAParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void validateBlackDuckParametersForMissingParametersTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);

        assertFalse(blackDuckSCAParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void validateBlackDuckParametersForNullAndEmptyTest() {
        assertFalse(blackDuckSCAParametersService.isValidBlackDuckParameters(null));

        Map<String, Object> blackDuckParametersMap = new HashMap<>();
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "");
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);

        assertFalse(blackDuckSCAParametersService.isValidBlackDuckParameters(blackDuckParametersMap));
    }

    @Test
    void prepareScanInputForBridgeForBlackduckAndProjectDirectoryTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);

        BlackDuck blackDuck = blackDuckSCAParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);
        Project project = blackDuckSCAParametersService.prepareProjectObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuck.getToken());
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
    }

    @Test
    void prepareScanBridgeInputForBlackduckArbitraryParamsTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY, 2);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_CONFIG_PATH_KEY, TEST_BLACKDUCKSCA_CONFIG_FILE_PATH);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_ARGS_KEY, TEST_BLACKDUCKSCA_ARGS);

        BlackDuck blackDuck = blackDuckSCAParametersService.prepareBlackDuckObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuck.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuck.getToken());
        assertEquals(2, blackDuck.getSearch().getDepth());
        assertEquals(TEST_BLACKDUCKSCA_CONFIG_FILE_PATH, blackDuck.getConfig().getPath());
        assertEquals(TEST_BLACKDUCKSCA_ARGS, blackDuck.getArgs());
    }
}
