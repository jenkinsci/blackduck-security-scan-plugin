package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.project.Project;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class BlackDuckSCASCAParametersServiceTest {
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
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");
        blackDuckParametersMap.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertNull(blackDuckSCA.getAutomation());
        assertEquals(true, blackDuckSCA.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuckSCA.getScan().getFailure().getSeverities());
    }

    @Test
    void createBlackDuckObjectForPRContextTest() {
        Map<String, Object> blackDuckParametersMap = new HashMap<>();

        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY, true);
        blackDuckParametersMap.put(ApplicationConstants.DETECT_SCAN_FULL_KEY, true);
        blackDuckParametersMap.put(
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY, "BLOCKER, CRITICAL, MAJOR, MINOR");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertEquals(true, blackDuckSCA.getAutomation().getPrComment());
        assertEquals(true, blackDuckSCA.getScan().getFull());
        assertEquals(
                List.of("BLOCKER", "CRITICAL", "MAJOR", "MINOR"),
                blackDuckSCA.getScan().getFailure().getSeverities());
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

        BlackDuckSCA blackDuckSCA =
                blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckParametersMap);
        Project project = blackDuckSCAParametersService.prepareProjectObjectForBridge(blackDuckParametersMap);

        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
    }
    //
    //    @Test
    //    void prepareScanBridgeInputForBlackduckArbitraryParamsTest() {
    //        Map<String, Object> blackDuckParametersMap = new HashMap<>();
    //
    //        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, TEST_BLACKDUCKSCA_URL);
    //        blackDuckParametersMap.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, TEST_BLACKDUCKSCA_TOKEN);
    //        blackDuckParametersMap.put(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY, 2);
    //        blackDuckParametersMap.put(ApplicationConstants.DETECT_CONFIG_PATH_KEY,
    // TEST_BLACKDUCKSCA_CONFIG_FILE_PATH);
    //        blackDuckParametersMap.put(ApplicationConstants.DETECT_ARGS_KEY, TEST_BLACKDUCKSCA_ARGS);
    //
    //        BlackDuckSCA blackDuckSCA =
    // blackDuckSCAParametersService.prepareBlackDuckSCAObjectForBridge(blackDuckParametersMap);
    //
    //        assertEquals(TEST_BLACKDUCKSCA_URL, blackDuckSCA.getUrl());
    //        assertEquals(TEST_BLACKDUCKSCA_TOKEN, blackDuckSCA.getToken());
    //        assertEquals(2, blackDuckSCA.getSearch().getDepth());
    //        assertEquals(TEST_BLACKDUCKSCA_CONFIG_FILE_PATH, blackDuckSCA.getConfig().getPath());
    //        assertEquals(TEST_BLACKDUCKSCA_ARGS, blackDuckSCA.getArgs());
    //    }
}
