package io.jenkins.plugins.security.scan.service.scan.coverity;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CoverityParametersServiceTest {
    private CoverityParametersService coverityParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_COVERITY_URL = "https://fake.coverity.url";
    private final String TEST_COVERITY_USER_NAME = "fake-user";
    private final String TEST_COVERITY_USER_PASSWORD = "fakeUserPassword";

    @BeforeEach
    void setUp() {
        coverityParametersService = new CoverityParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        assertFalse(coverityParametersService.hasAllMandatoryCoverityParams(coverityParameters));

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);

        assertFalse(coverityParametersService.hasAllMandatoryCoverityParams(coverityParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");

        assertTrue(coverityParametersService.hasAllMandatoryCoverityParams(coverityParameters));
    }

    @Test
    void prepareCoverityObjectForBridgeNonPRContextTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, "2023.6.0");
        coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, true);
        coverityParameters.put(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY, true);

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getCoverityProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(coverity.getVersion(), "2023.6.0");
        assertTrue(coverity.isLocal());
        assertNull(coverity.getAutomation());
    }

    @Test
    void prepareCoverityObjectForBridgePRContextTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.COVERITY_VERSION_KEY, "2023.6.0");
        coverityParameters.put(ApplicationConstants.COVERITY_LOCAL_KEY, true);
        coverityParameters.put(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY, true);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getCoverityProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(coverity.getVersion(), "2023.6.0");
        assertTrue(coverity.isLocal());
        assertTrue(coverity.getAutomation().getPrComment());
    }

    @Test
    void prepareCoverityObjectForBridgePRContext_withDefaultValueTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY, true);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");
        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_TARGET_KEY))
                .thenReturn("main");

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getCoverityProject().getName(), "default-repo-name");
        assertEquals(coverity.getConnect().getStream().getName(), "default-repo-name-main");
        assertTrue(coverity.getAutomation().getPrComment());
    }

    @Test
    void prepareCoverityObjectForBridgeNonPRContext_withDefaultValueTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_BRANCH_NAME_KEY)).thenReturn("feature");

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getCoverityProject().getName(), "default-repo-name");
        assertEquals(coverity.getConnect().getStream().getName(), "default-repo-name-feature");
    }

    @Test
    void prepareCoverityObjectForBridgeForCoverityAndProjectDirectoryTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_PROJECT_NAME_KEY, "fake-repo");
        coverityParameters.put(ApplicationConstants.COVERITY_STREAM_NAME_KEY, "fake-repo-branch");
        coverityParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, "DIR/TEST");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);
        Project project = coverityParametersService.prepareProjectObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getConnect().getCoverityProject().getName(), "fake-repo");
        assertEquals(coverity.getConnect().getStream().getName(), "fake-repo-branch");
        assertEquals(project.getDirectory(), "DIR/TEST");
    }

    @Test
    void prepareCoverityObjectForBridgeForCoverityArbitraryParamsTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_URL_KEY, TEST_COVERITY_URL);
        coverityParameters.put(ApplicationConstants.COVERITY_USER_KEY, TEST_COVERITY_USER_NAME);
        coverityParameters.put(ApplicationConstants.COVERITY_PASSPHRASE_KEY, TEST_COVERITY_USER_PASSWORD);
        coverityParameters.put(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY, "mvn clean install");
        coverityParameters.put(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY, "mvn clean");
        coverityParameters.put(ApplicationConstants.COVERITY_CONFIG_PATH_KEY, "DIR/CONFIG/coverity.yml");
        coverityParameters.put(
                ApplicationConstants.COVERITY_ARGS_KEY,
                "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");

        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(coverityParameters);

        assertEquals(coverity.getConnect().getUrl(), TEST_COVERITY_URL);
        assertEquals(coverity.getConnect().getUser().getName(), TEST_COVERITY_USER_NAME);
        assertEquals(coverity.getConnect().getUser().getPassword(), TEST_COVERITY_USER_PASSWORD);
        assertEquals(coverity.getBuild().getCommand(), "mvn clean install");
        assertEquals(coverity.getClean().getCommand(), "mvn clean");
        assertEquals(coverity.getConfig().getPath(), "DIR/CONFIG/coverity.yml");
        assertEquals(coverity.getArgs(), "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
    }

    @Test
    void setArbitaryInputsTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        coverityParameters.put(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY, "mvn clean install");
        coverityParameters.put(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY, "mvn clean");
        coverityParameters.put(ApplicationConstants.COVERITY_CONFIG_PATH_KEY, "DIR/CONFIG/coverity.yml");
        coverityParameters.put(
                ApplicationConstants.COVERITY_ARGS_KEY,
                "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
        coverityParameters.put(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY, "test/path");

        Coverity coverity = coverityParametersService.setArbitaryInputs(coverityParameters, null);

        assertNotNull(coverity);
        assertEquals(coverity.getBuild().getCommand(), "mvn clean install");
        assertEquals(coverity.getClean().getCommand(), "mvn clean");
        assertEquals(coverity.getConfig().getPath(), "DIR/CONFIG/coverity.yml");
        assertEquals(coverity.getArgs(), "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
        assertEquals(coverity.getExecution().getPath(), "test/path");
    }

    @Test
    void setArbitaryInputs_forEmptyParametersTest() {
        Map<String, Object> coverityParameters = new HashMap<>();

        Coverity coverity = coverityParametersService.setArbitaryInputs(coverityParameters, null);

        assertNull(coverity);
    }
}
