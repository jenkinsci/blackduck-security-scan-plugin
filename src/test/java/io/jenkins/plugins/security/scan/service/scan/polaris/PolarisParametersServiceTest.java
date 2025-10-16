package io.jenkins.plugins.security.scan.service.scan.polaris;

import static org.junit.jupiter.api.Assertions.*;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.report.Sarif;
import io.jenkins.plugins.security.scan.service.scan.coverity.CoverityParametersService;
import io.jenkins.plugins.security.scan.service.scm.RepositoryDetailsHolder;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class PolarisParametersServiceTest {
    private PolarisParametersService polarisParametersService;
    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private final String TEST_POLARIS_SERVER_URL = "https://fake.polaris-server.url";
    private final String TEST_POLARIS_ACCESS_TOKEN = "fakePolarisAccessToken";
    private final String TEST_APPLICATION_NAME = "fake-polaris-application-name";
    private final String TEST_POLARIS_ASSESSMENT_MODE = "SOURCE_UPLOAD";
    private final String TEST_PROJECT_DIRECTORY = "DIR/TEST";
    private final String TEST_PROJECT_SOURCE_ARCHIVE = "TEST.ZIP";
    private final Boolean TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS = true;

    @BeforeEach
    void setUp() {
        polarisParametersService = new PolarisParametersService(listenerMock, envVarsMock);
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void invalidScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        assertFalse(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);

        assertFalse(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));
    }

    @Test
    void validScanParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-polaris-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SCA, SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "HIGH, CRITICAL");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY, TEST_POLARIS_ASSESSMENT_MODE);
        polarisParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY, TEST_PROJECT_SOURCE_ARCHIVE);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY, "TEST1, TEST2");
        polarisParameters.put(
                ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY, TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS);
        polarisParameters.put(ApplicationConstants.POLARIS_WAITFORSCAN_KEY, true);

        assertTrue(polarisParametersService.hasAllMandatoryCoverityParams(polarisParameters));
    }

    @Test
    void preparePolarisObjectForBridge_inNonPPContextTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "HIGH");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, "SCA-PACKAGE");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_TYPE_KEY, "SAST_RAPID");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_LOCATION_KEY, "hybrid");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "remote");

        polarisParameters.put(ApplicationConstants.POLARIS_WAITFORSCAN_KEY, true);

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getPolarisProject().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SAST"));
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertEquals(polaris.getTest().getSca().getType(), "SCA-PACKAGE");
        assertEquals(polaris.getTest().getSast().getType(), List.of("SAST_RAPID"));
		assertEquals(polaris.getTest().getSca().getLocation(), "hybrid");
		assertEquals(polaris.getTest().getSast().getLocation(), "remote");
        assertNull(polaris.getBranch().getParent());
        assertNull(polaris.getPrcomment());
        assertEquals(polaris.isWaitForScan(), true);
    }

    @Test
    void preparePolarisObjectForBridge_inNonPPContext_withSarifParametersTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "HIGH");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, "SCA-PACKAGE");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_TYPE_KEY, "SAST_RAPID");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_LOCATION_KEY, "hybrid");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "remote");
        polarisParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        polarisParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        polarisParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY, "SCA");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getPolarisProject().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SAST"));
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertEquals(polaris.getTest().getSca().getType(), "SCA-PACKAGE");
        assertEquals(polaris.getTest().getSast().getType(), List.of("SAST_RAPID"));
		assertEquals(polaris.getTest().getSca().getLocation(), "hybrid");
		assertEquals(polaris.getTest().getSast().getLocation(), "remote");
        assertNull(polaris.getBranch().getParent());
        assertNull(polaris.getPrcomment());
        assertTrue(polaris.getReports().getSarif().getCreate());
        assertEquals(
                "/path/to/sarif/file", polaris.getReports().getSarif().getFile().getPath());
        assertEquals(
                Arrays.asList("HIGH", "MEDIUM", "LOW"),
                polaris.getReports().getSarif().getSeverities());
        assertEquals(List.of("SCA"), polaris.getReports().getSarif().getIssue().getTypes());
        assertTrue(polaris.getReports().getSarif().getGroupSCAIssues());
    }

    @Test
    void preparePolarisObjectForBridge_inPPContextTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_NAME_KEY, "test-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY, "test-parent-branch");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY, "CRITICAL, HIGH, MEDIUM");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY, "SCA-SIGNATURE");
        polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_TYPE_KEY, "SAST_RAPID");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_LOCATION_KEY, "hybrid");
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "remote");
        polarisParameters.put(ApplicationConstants.POLARIS_WAITFORSCAN_KEY, true);

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getPolarisProject().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SAST"));
        assertEquals(polaris.getBranch().getName(), "test-branch");
        assertEquals(polaris.getBranch().getParent().getName(), "test-parent-branch");
        assertEquals(polaris.getPrcomment().getEnabled(), true);
        assertEquals(polaris.getPrcomment().getSeverities(), List.of("CRITICAL", "HIGH", "MEDIUM"));
        assertEquals(polaris.getTest().getSca().getType(), "SCA-SIGNATURE");
        assertEquals(polaris.getTest().getSast().getType(), List.of("SAST_RAPID"));
        assertEquals(polaris.isWaitForScan(), true);
    }

    @Test
    void preparePolarisObjectForBridge_inNonPPContext_withDefaultValueTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SCA,SAST");

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_BRANCH_NAME_KEY)).thenReturn("feature");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), "default-repo-name");
        assertEquals(polaris.getPolarisProject().getName(), "default-repo-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SCA", "SAST"));
        assertEquals(polaris.getBranch().getName(), "feature");
    }

    @Test
    void preparePolarisObjectForBridge_inPPContext_withDefaultValueTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SCA,SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY, true);

        RepositoryDetailsHolder.setRepositoryName("default-repo-name");

        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_ID_KEY)).thenReturn("1");
        Mockito.when(envVarsMock.get(ApplicationConstants.ENV_CHANGE_BRANCH_KEY))
                .thenReturn("main");

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), "default-repo-name");
        assertEquals(polaris.getPolarisProject().getName(), "default-repo-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SCA", "SAST"));
        assertEquals(polaris.getBranch().getName(), "main");
        assertTrue(polaris.getPrcomment().getEnabled());
    }

    @Test
    void preparePolarisObjectForBridge_forPolarisSourceUploadTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY, TEST_POLARIS_ASSESSMENT_MODE);
        polarisParameters.put(ApplicationConstants.PROJECT_DIRECTORY_KEY, TEST_PROJECT_DIRECTORY);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY, TEST_PROJECT_SOURCE_ARCHIVE);
        polarisParameters.put(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY, "TEST");
        polarisParameters.put(
                ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY, TEST_PROJECT_SOURCE_PRESERVE_SYM_LINKS);

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);
        Project project = polarisParametersService.prepareProjectObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getPolarisProject().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SAST"));
        assertEquals(polaris.getAssessmentTypes().getMode(), TEST_POLARIS_ASSESSMENT_MODE);
        assertEquals(project.getDirectory(), TEST_PROJECT_DIRECTORY);
        assertEquals(project.getSource().getArchive(), TEST_PROJECT_SOURCE_ARCHIVE);
        assertEquals(project.getSource().getExcludes(), List.of("TEST"));
        assertTrue(project.getSource().getPreserveSymLinks());
    }

    @Test
    void preparePolarisObjectForBridge_forArbitraryParamsTest() {
        Map<String, Object> polarisParameters = new HashMap<>();

        polarisParameters.put(ApplicationConstants.POLARIS_SERVER_URL_KEY, TEST_POLARIS_SERVER_URL);
        polarisParameters.put(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY, TEST_POLARIS_ACCESS_TOKEN);
        polarisParameters.put(ApplicationConstants.POLARIS_APPLICATION_NAME_KEY, TEST_APPLICATION_NAME);
        polarisParameters.put(ApplicationConstants.POLARIS_PROJECT_NAME_KEY, "fake-project-name");
        polarisParameters.put(ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY, "SAST");
        polarisParameters.put(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY, 2);
        polarisParameters.put(ApplicationConstants.DETECT_CONFIG_PATH_KEY, "DIR/CONFIG/application.properties");
        polarisParameters.put(ApplicationConstants.DETECT_ARGS_KEY, "--detect.diagnostic=true");
        polarisParameters.put(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY, "mvn clean install");
        polarisParameters.put(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY, "mvn clean");
        polarisParameters.put(ApplicationConstants.COVERITY_CONFIG_PATH_KEY, "DIR/CONFIG/coverity.yml");
        polarisParameters.put(
                ApplicationConstants.COVERITY_ARGS_KEY,
                "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");

        CoverityParametersService coverityParametersService = new CoverityParametersService(listenerMock, envVarsMock);

        Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);
        Coverity coverity = coverityParametersService.prepareCoverityObjectForBridge(polarisParameters);

        assertEquals(polaris.getServerUrl(), TEST_POLARIS_SERVER_URL);
        assertEquals(polaris.getAccessToken(), TEST_POLARIS_ACCESS_TOKEN);
        assertEquals(polaris.getApplicationName().getName(), TEST_APPLICATION_NAME);
        assertEquals(polaris.getPolarisProject().getName(), "fake-project-name");
        assertEquals(polaris.getAssessmentTypes().getTypes(), List.of("SAST"));
        assertEquals(coverity.getBuild().getCommand(), "mvn clean install");
        assertEquals(coverity.getClean().getCommand(), "mvn clean");
        assertEquals(coverity.getConfig().getPath(), "DIR/CONFIG/coverity.yml");
        assertEquals(coverity.getArgs(), "-o capture.build.clean-command=\"mvn clean\" -- mvn clean install");
    }

    @Test
    public void preparePolarisSarifObjectTest() {
        Map<String, Object> scanParameters = new HashMap<>();

        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY, true);
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY, "/path/to/sarif/file");
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,MEDIUM,LOW");
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY, true);
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY, "SCA");

        Sarif sarifObject = polarisParametersService.prepareSarifObject(scanParameters);

        assertNotNull(sarifObject);
        assertTrue(sarifObject.getCreate());
        assertEquals("/path/to/sarif/file", sarifObject.getFile().getPath());
        assertEquals(Arrays.asList("HIGH", "MEDIUM", "LOW"), sarifObject.getSeverities());
        assertEquals(List.of("SCA"), sarifObject.getIssue().getTypes());
        assertTrue(sarifObject.getGroupSCAIssues());
    }

    @Test
    public void preparePolarisSarifObjectWithDefaultPathTest() {
        Map<String, Object> scanParameters = new HashMap<>();
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY, true);
        // Do not set POLARIS_REPORTS_SARIF_FILE_PATH_KEY to test default path
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY, "HIGH,LOW");
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY, false);
        scanParameters.put(ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY, "SAST");

        Sarif sarifObject = polarisParametersService.prepareSarifObject(scanParameters);

        assertNotNull(sarifObject);
        assertTrue(sarifObject.getCreate());
        assertNotNull(sarifObject.getFile());
        assertEquals(
                ApplicationConstants.DEFAULT_POLARIS_SARIF_REPORT_FILE_PATH
                        + ApplicationConstants.SARIF_REPORT_FILENAME,
                sarifObject.getFile().getPath());
        assertEquals(Arrays.asList("HIGH", "LOW"), sarifObject.getSeverities());
        assertEquals(List.of("SAST"), sarifObject.getIssue().getTypes());
        assertFalse(sarifObject.getGroupSCAIssues());
    }

	@Test
	void testSastLocationSetToLocal() {
		Map<String, Object> polarisParameters = new HashMap<>();
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "local");

		Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

		assertEquals("local", polaris.getTest().getSast().getLocation());
	}

	@Test
	void testSastLocationSetToHybrid() {
		Map<String, Object> polarisParameters = new HashMap<>();
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "hybrid");

		Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

		assertEquals("hybrid", polaris.getTest().getSast().getLocation());
	}

	@Test
	void testSastLocationSetToRemote() {
		Map<String, Object> polarisParameters = new HashMap<>();
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SAST_LOCATION_KEY, "remote");

		Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

		assertEquals("remote", polaris.getTest().getSast().getLocation());
	}

	@Test
	void testScaLocationSetToHybrid() {
		Map<String, Object> polarisParameters = new HashMap<>();
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_LOCATION_KEY, "hybrid");

		Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

		assertEquals("hybrid", polaris.getTest().getSca().getLocation());
	}

	@Test
	void testScaLocationSetToRemote() {
		Map<String, Object> polarisParameters = new HashMap<>();
		polarisParameters.put(ApplicationConstants.POLARIS_TEST_SCA_LOCATION_KEY, "remote");

		Polaris polaris = polarisParametersService.preparePolarisObjectForBridge(polarisParameters);

		assertEquals("remote", polaris.getTest().getSca().getLocation());
	}
}
