package io.jenkins.plugins.security.scan.service.scan.srm;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.detect.Detect;
import io.jenkins.plugins.security.scan.input.srm.SRM;
import io.jenkins.plugins.security.scan.service.scan.blackducksca.DetectParametersService;
import io.jenkins.plugins.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class SRMParametersServiceTest {

    private SRMParametersService srmParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_SRM_SERVER_URL = "https://fake.srm-server.url";
    private final String TEST_SRM_API_KEY_TOKEN = "fakeSrmAPIKey";
    private final String TEST_SRM_PROJECT_NAME = "fake-srm-project-name";
    private final String TEST_SRM_PROJECT_ID = "fake-srm-project-id";
    private final String TEST_SRM_ASSESSMENT_TYPES = "SCA";
    private final String TEST_SRM_BRANCH_NAME = "test-branch";
    private final String TEST_SRM_BRANCH_PARENT_NAME = "test-parent-branch";

    @BeforeEach
    void setUp() {
        srmParametersService = new SRMParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        assertFalse(srmParametersService.hasAllMandatorySrmParams(srmParameters));

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);

        assertFalse(srmParametersService.hasAllMandatorySrmParams(srmParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, TEST_SRM_PROJECT_NAME);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, TEST_SRM_PROJECT_ID);
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, TEST_SRM_ASSESSMENT_TYPES);
        srmParameters.put(ApplicationConstants.SRM_BRANCH_NAME_KEY, TEST_SRM_BRANCH_NAME);
        srmParameters.put(ApplicationConstants.SRM_BRANCH_PARENT_KEY, TEST_SRM_BRANCH_PARENT_NAME);
        srmParameters.put(ApplicationConstants.SRM_WAITFORSCAN_KEY, true);

        assertTrue(srmParametersService.hasAllMandatorySrmParams(srmParameters));
    }

    @Test
    void prepareSrmObjectForBridge_arbitraryParamsTest() {
        Map<String, Object> srmParameters = new HashMap<>();
        srmParameters.put(ApplicationConstants.PRODUCT_KEY, SecurityProduct.SRM.name());
        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_NAME_KEY, TEST_SRM_PROJECT_NAME);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, TEST_SRM_PROJECT_ID);
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, TEST_SRM_ASSESSMENT_TYPES);
        srmParameters.put(ApplicationConstants.SRM_BRANCH_NAME_KEY, TEST_SRM_BRANCH_NAME);
        srmParameters.put(ApplicationConstants.SRM_BRANCH_PARENT_KEY, TEST_SRM_BRANCH_PARENT_NAME);

        srmParameters.put(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY, 2);
        srmParameters.put(ApplicationConstants.DETECT_CONFIG_PATH_KEY, "DIR/CONFIG/application.properties");
        srmParameters.put(ApplicationConstants.DETECT_ARGS_KEY, "--detect.diagnostic=true");
        srmParameters.put(ApplicationConstants.DETECT_EXECUTION_PATH_KEY, "/fake/path/bd");

        srmParameters.put(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY, "mvn clean install");
        srmParameters.put(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY, "mvn clean");
        srmParameters.put(ApplicationConstants.COVERITY_CONFIG_PATH_KEY, "DIR/CONFIG/coverity.yml");
        srmParameters.put(
                ApplicationConstants.COVERITY_ARGS_KEY,
                "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
        srmParameters.put(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY, "/fake/path/cov");

        DetectParametersService detectParametersService = new DetectParametersService();
        CoverityParametersService coverityParametersService = new CoverityParametersService(listenerMock, envVarsMock);

        SRM srm = srmParametersService.prepareSrmObjectForBridge(srmParameters);
        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(srmParameters);
        Detect detect = detectParametersService.prepareDetectObject(srmParameters);

        assertEquals(srm.getUrl(), TEST_SRM_SERVER_URL);
        assertEquals(srm.getApikey(), TEST_SRM_API_KEY_TOKEN);
        assertEquals(srm.getSrmProject().getName(), TEST_SRM_PROJECT_NAME);
        assertEquals(srm.getSrmProject().getId(), TEST_SRM_PROJECT_ID);
        assertEquals(srm.getBranch().getName(), TEST_SRM_BRANCH_NAME);
        assertEquals(srm.getBranch().getParent(), TEST_SRM_BRANCH_PARENT_NAME);
        assertEquals(srm.getAssessmentTypes().getTypes(), List.of(TEST_SRM_ASSESSMENT_TYPES));
        assertEquals(detect.getSearch().getDepth(), 2);
        assertEquals(detect.getConfig().getPath(), "DIR/CONFIG/application.properties");
        assertEquals(detect.getArgs(), "--detect.diagnostic=true");
        assertEquals(detect.getExecution().getPath(), "/fake/path/bd");
        assertEquals(coverity.getBuild().getCommand(), "mvn clean install");
        assertEquals(coverity.getClean().getCommand(), "mvn clean");
        assertEquals(coverity.getConfig().getPath(), "DIR/CONFIG/coverity.yml");
        assertEquals(coverity.getArgs(), "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
    }

    @Test
    void prepareScanInputForBridge_withDefaultValue_withoutProjectIdTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, TEST_SRM_ASSESSMENT_TYPES);

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        SRM srm = srmParametersService.prepareSrmObjectForBridge(srmParameters);

        assertEquals(srm.getUrl(), TEST_SRM_SERVER_URL);
        assertEquals(srm.getApikey(), TEST_SRM_API_KEY_TOKEN);
        assertEquals(srm.getSrmProject().getName(), "default-repo-name");
        assertNull(srm.getSrmProject().getId());
        assertEquals(srm.getAssessmentTypes().getTypes(), List.of(TEST_SRM_ASSESSMENT_TYPES));
    }

    @Test
    void prepareScanInputForBridge_withDefaultValue_withProjectIdTest() {
        Map<String, Object> srmParameters = new HashMap<>();

        srmParameters.put(ApplicationConstants.SRM_URL_KEY, TEST_SRM_SERVER_URL);
        srmParameters.put(ApplicationConstants.SRM_APIKEY_KEY, TEST_SRM_API_KEY_TOKEN);
        srmParameters.put(ApplicationConstants.SRM_PROJECT_ID_KEY, TEST_SRM_PROJECT_ID);
        srmParameters.put(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY, TEST_SRM_ASSESSMENT_TYPES);

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        SRM srm = srmParametersService.prepareSrmObjectForBridge(srmParameters);

        assertEquals(srm.getUrl(), TEST_SRM_SERVER_URL);
        assertEquals(srm.getApikey(), TEST_SRM_API_KEY_TOKEN);
        assertNull(srm.getSrmProject().getName());
        assertEquals(srm.getSrmProject().getId(), TEST_SRM_PROJECT_ID);
        assertEquals(srm.getAssessmentTypes().getTypes(), List.of(TEST_SRM_ASSESSMENT_TYPES));
    }
}
