package io.jenkins.plugins.security.scan.service;

import static org.junit.jupiter.api.Assertions.*;

import hudson.FilePath;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.extension.freestyle.BlackDuckScanFreestyle;
import io.jenkins.plugins.security.scan.extension.pipeline.BlackDuckScanStep;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.enums.BuildStatus;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import java.io.File;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class ParameterMappingServiceTest {
    private TaskListener listenerMock;
    private FilePath workspace;
    private BlackDuckScanStep blackDuckScanStep;
    private BlackDuckScanFreestyle blackDuckScanFreestyle;

    @BeforeEach
    public void setUp() {
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        blackDuckScanStep = new BlackDuckScanStep();
        blackDuckScanFreestyle = new BlackDuckScanFreestyle();
        ParameterMappingService.getDeprecatedParameters().clear();
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
    }

    @Test
    void testGetDeprecatedParameters_initiallyEmpty() {
        List<String> deprecatedParameters = ParameterMappingService.getDeprecatedParameters();
        assertTrue(deprecatedParameters.isEmpty(), "DEPRECATED_PARAMETERS should be initially empty");
    }

    @Test
    void testGetDeprecatedParameters_reflectsInternalChanges() {
        ParameterMappingService.addDeprecatedParameter("param1");
        ParameterMappingService.addDeprecatedParameter("param2");

        List<String> deprecatedParameters = ParameterMappingService.getDeprecatedParameters();
        assertEquals(2, deprecatedParameters.size());
        assertTrue(deprecatedParameters.contains("param1"));
        assertTrue(deprecatedParameters.contains("param2"));
    }

    @Test
    public void preparePipelineParametersMapTest() throws PluginExceptionHandler {
        Map<String, Object> globalConfigValues = new HashMap<>();

        blackDuckScanStep.setProduct("BLACKDUCKSCA");
        blackDuckScanStep.setBitbucket_token("FAKETOKEN");
        blackDuckScanStep.setGithub_token("faketoken-github");
        blackDuckScanStep.setGitlab_token("fakeTokeN-gItlAb");
        globalConfigValues.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake-blackduck.url");
        globalConfigValues.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "fake-blackduck-token");
        globalConfigValues.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/fake/path");

        Map<String, Object> result = ParameterMappingService.preparePipelineParametersMap(
                blackDuckScanStep, globalConfigValues, listenerMock);

        assertEquals(8, result.size());
        assertEquals("BLACKDUCKSCA", result.get(ApplicationConstants.PRODUCT_KEY));
        assertEquals("fake-blackduck-token", result.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", result.get(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY));
        assertEquals("FAKETOKEN", result.get(ApplicationConstants.BITBUCKET_TOKEN_KEY));
        assertEquals("faketoken-github", result.get(ApplicationConstants.GITHUB_TOKEN_KEY));
        assertEquals("fakeTokeN-gItlAb", result.get(ApplicationConstants.GITLAB_TOKEN_KEY));

        blackDuckScanStep.setProduct("invalid-product");

        assertThrows(
                PluginExceptionHandler.class,
                () -> ParameterMappingService.preparePipelineParametersMap(
                        blackDuckScanStep, globalConfigValues, listenerMock));
    }

    @Test
    public void prepareBlackDuckParametersMapTestForMultibranchTest() {
        blackDuckScanStep.setBlackducksca_url("https://fake.blackduck-url");
        blackDuckScanStep.setBlackducksca_token("fake-token");
        blackDuckScanStep.setDetect_install_directory("/fake/path");
        blackDuckScanStep.setDetect_scan_full(true);
        blackDuckScanStep.setBlackducksca_prComment_enabled(true);
        blackDuckScanStep.setDetect_download_url("https://fake.blackduck-download-url");
        blackDuckScanStep.setBlackducksca_scan_failure_severities("MAJOR");
        blackDuckScanStep.setProject_directory("test/directory");
        blackDuckScanStep.setDetect_search_depth(2);
        blackDuckScanStep.setDetect_config_path("fake/directory/application.properties");
        blackDuckScanStep.setDetect_args("--o");

        Map<String, Object> blackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckParametersMap(blackDuckScanStep);

        assertEquals(11, blackDuckParametersMap.size());
        assertEquals(
                "https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.DETECT_SCAN_FULL_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY));
        assertEquals(
                "MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY));
        assertEquals("test/directory", blackDuckParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals(2, blackDuckParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/directory/application.properties",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_CONFIG_PATH_KEY));
        assertEquals("--o", blackDuckParametersMap.get(ApplicationConstants.DETECT_ARGS_KEY));
        Map<String, Object> emptyBlackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptyBlackDuckParametersMap.size());
    }

    @Test
    public void prepareBlackDuckParametersMapTestsMapForFreestyleTest() {
        blackDuckScanFreestyle.setBlackducksca_url("https://fake.blackduck-url");
        blackDuckScanFreestyle.setBlackducksca_token("fake-token");
        blackDuckScanFreestyle.setDetect_install_directory("/fake/path");
        blackDuckScanFreestyle.setDetect_scan_full(true);
        blackDuckScanFreestyle.setDetect_download_url("https://fake.blackduck-download-url");
        blackDuckScanFreestyle.setBlackducksca_scan_failure_severities("MAJOR");
        blackDuckScanFreestyle.setProject_directory("test/directory");
        blackDuckScanFreestyle.setDetect_search_depth(2);
        blackDuckScanFreestyle.setDetect_config_path("fake/directory/application.properties");
        blackDuckScanFreestyle.setDetect_args("--o");

        Map<String, Object> blackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckParametersMap(blackDuckScanFreestyle);

        assertEquals(10, blackDuckParametersMap.size());
        assertEquals(
                "https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.DETECT_SCAN_FULL_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY));
        assertEquals(
                "MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY));
        assertEquals("test/directory", blackDuckParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals(2, blackDuckParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/directory/application.properties",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_CONFIG_PATH_KEY));
        assertEquals("--o", blackDuckParametersMap.get(ApplicationConstants.DETECT_ARGS_KEY));
        Map<String, Object> emptyBlackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptyBlackDuckParametersMap.size());
    }

    @Test
    public void prepareCoverityParametersMapTestForMultibranchTest() {
        blackDuckScanStep.setCoverity_url("https://fake.coverity-url");
        blackDuckScanStep.setCoverity_user("fake-user");
        blackDuckScanStep.setCoverity_passphrase("fake-passphrase");
        blackDuckScanStep.setCoverity_project_name("fake-project");
        blackDuckScanStep.setCoverity_stream_name("fake-stream");
        blackDuckScanStep.setCoverity_policy_view("fake-policy");
        blackDuckScanStep.setCoverity_install_directory("/fake/path");
        blackDuckScanStep.setCoverity_prComment_enabled(true);
        blackDuckScanStep.setCoverity_version("1.0.0");
        blackDuckScanStep.setCoverity_local(true);
        blackDuckScanStep.setProject_directory("test/directory");
        blackDuckScanStep.setCoverity_build_command("fake-build-command");
        blackDuckScanStep.setCoverity_clean_command("fake-clean-command");
        blackDuckScanStep.setCoverity_config_path("fake-config-path");
        blackDuckScanStep.setCoverity_args("--o");

        Map<String, Object> coverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(blackDuckScanStep);

        assertEquals(15, coverityParametersMap.size());
        assertEquals("https://fake.coverity-url", coverityParametersMap.get(ApplicationConstants.COVERITY_URL_KEY));
        assertEquals("fake-user", coverityParametersMap.get(ApplicationConstants.COVERITY_USER_KEY));
        assertEquals("fake-passphrase", coverityParametersMap.get(ApplicationConstants.COVERITY_PASSPHRASE_KEY));
        assertEquals("fake-project", coverityParametersMap.get(ApplicationConstants.COVERITY_PROJECT_NAME_KEY));
        assertEquals("fake-stream", coverityParametersMap.get(ApplicationConstants.COVERITY_STREAM_NAME_KEY));
        assertEquals("fake-policy", coverityParametersMap.get(ApplicationConstants.COVERITY_POLICY_VIEW_KEY));
        assertEquals("/fake/path", coverityParametersMap.get(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) coverityParametersMap.get(ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY));
        assertEquals("1.0.0", coverityParametersMap.get(ApplicationConstants.COVERITY_VERSION_KEY));
        assertTrue(coverityParametersMap.containsKey(ApplicationConstants.COVERITY_LOCAL_KEY));
        assertEquals("test/directory", coverityParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-build-command", coverityParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("fake-clean-command", coverityParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake-config-path", coverityParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", coverityParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));

        Map<String, Object> emptyCoverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(new BlackDuckScanStep());
        assertEquals(0, emptyCoverityParametersMap.size());
    }

    @Test
    public void prepareCoverityParametersMapForFreestyleTest() {
        blackDuckScanFreestyle.setCoverity_url("https://fake.coverity-url");
        blackDuckScanFreestyle.setCoverity_user("fake-user");
        blackDuckScanFreestyle.setCoverity_passphrase("fake-passphrase");
        blackDuckScanFreestyle.setCoverity_project_name("fake-project");
        blackDuckScanFreestyle.setCoverity_stream_name("fake-stream");
        blackDuckScanFreestyle.setCoverity_policy_view("fake-policy");
        blackDuckScanFreestyle.setCoverity_install_directory("/fake/path");
        blackDuckScanFreestyle.setCoverity_version("1.0.0");
        blackDuckScanFreestyle.setCoverity_local(true);
        blackDuckScanFreestyle.setProject_directory("test/directory");
        blackDuckScanFreestyle.setCoverity_build_command("fake-build-command");
        blackDuckScanFreestyle.setCoverity_clean_command("fake-clean-command");
        blackDuckScanFreestyle.setCoverity_config_path("fake-config-path");
        blackDuckScanFreestyle.setCoverity_args("--o");

        Map<String, Object> coverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(blackDuckScanFreestyle);

        assertEquals(14, coverityParametersMap.size());
        assertEquals("https://fake.coverity-url", coverityParametersMap.get(ApplicationConstants.COVERITY_URL_KEY));
        assertEquals("fake-user", coverityParametersMap.get(ApplicationConstants.COVERITY_USER_KEY));
        assertEquals("fake-passphrase", coverityParametersMap.get(ApplicationConstants.COVERITY_PASSPHRASE_KEY));
        assertEquals("fake-project", coverityParametersMap.get(ApplicationConstants.COVERITY_PROJECT_NAME_KEY));
        assertEquals("fake-stream", coverityParametersMap.get(ApplicationConstants.COVERITY_STREAM_NAME_KEY));
        assertEquals("fake-policy", coverityParametersMap.get(ApplicationConstants.COVERITY_POLICY_VIEW_KEY));
        assertEquals("/fake/path", coverityParametersMap.get(ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY));
        assertEquals("1.0.0", coverityParametersMap.get(ApplicationConstants.COVERITY_VERSION_KEY));
        assertTrue(coverityParametersMap.containsKey(ApplicationConstants.COVERITY_LOCAL_KEY));
        assertEquals("test/directory", coverityParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-build-command", coverityParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("fake-clean-command", coverityParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake-config-path", coverityParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", coverityParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));

        Map<String, Object> emptyCoverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(new BlackDuckScanStep());
        assertEquals(0, emptyCoverityParametersMap.size());
    }

    @Test
    public void prepareBridgeParametersMapTest() {
        blackDuckScanStep.setBridgecli_download_url("https://fake.bridge-download.url");
        blackDuckScanStep.setBridgecli_download_version("1.0.0");
        blackDuckScanStep.setBridgecli_install_directory("/fake/path");
        blackDuckScanStep.setInclude_diagnostics(true);
        blackDuckScanStep.setNetwork_airgap(true);

        Map<String, Object> bridgeParametersMap =
                ParameterMappingService.prepareAddtionalParametersMap(blackDuckScanStep);

        assertEquals(5, bridgeParametersMap.size());
        assertEquals(
                "https://fake.bridge-download.url",
                bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL));
        assertEquals("1.0.0", bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION));
        assertEquals("/fake/path", bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.NETWORK_AIRGAP_KEY));

        Map<String, Object> emptyBridgeParametersMap =
                ParameterMappingService.prepareAddtionalParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptyBridgeParametersMap.size());
    }

    @Test
    public void preparePolarisParametersMapForMultibranchTest() {
        blackDuckScanStep.setPolaris_server_url("https://fake.polaris-server.url");
        blackDuckScanStep.setPolaris_access_token("fake-access-token");
        blackDuckScanStep.setPolaris_application_name("fake-application-name");
        blackDuckScanStep.setPolaris_project_name("fake-project-name");
        blackDuckScanStep.setPolaris_assessment_types("SCA");
        blackDuckScanStep.setPolaris_triage("REQUIRED");
        blackDuckScanStep.setPolaris_branch_name("test");
        blackDuckScanStep.setPolaris_branch_parent_name("master");
        blackDuckScanStep.setPolaris_prComment_enabled(true);
        blackDuckScanStep.setPolaris_prComment_severities("high, critical");
        blackDuckScanStep.setPolaris_assessment_mode("SOURCE_UPLOAD");
        blackDuckScanStep.setProject_directory("test/directory");
        blackDuckScanStep.setProject_source_archive("fake-source-archive");
        blackDuckScanStep.setProject_source_preserveSymLinks(true);
        blackDuckScanStep.setProject_source_excludes("test_exclude");

        Map<String, Object> polarisParametersMap =
                ParameterMappingService.preparePolarisParametersMap(blackDuckScanStep);

        assertEquals(15, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("REQUIRED", polarisParametersMap.get(ApplicationConstants.POLARIS_TRIAGE_KEY));
        assertEquals("master", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY));
        assertEquals(true, polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY));
        assertEquals("high, critical", polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY));
        assertEquals("SOURCE_UPLOAD", polarisParametersMap.get(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY));
        assertEquals("test/directory", polarisParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-source-archive", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY));
        assertEquals("test_exclude", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY));
        assertTrue((Boolean) polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY));
    }

    @Test
    public void preparePolarisParametersMapForFreestyleTest() {
        blackDuckScanFreestyle.setProduct("POLARIS");
        blackDuckScanFreestyle.setBitbucket_token("FAKETOKEN");
        blackDuckScanFreestyle.setGithub_token("faketoken-github");
        blackDuckScanFreestyle.setGitlab_token("fakeTokeN-gItlAb");
        blackDuckScanFreestyle.setPolaris_server_url("https://fake.polaris-server.url");
        blackDuckScanFreestyle.setPolaris_access_token("fake-access-token");
        blackDuckScanFreestyle.setPolaris_application_name("fake-application-name");
        blackDuckScanFreestyle.setPolaris_project_name("fake-project-name");
        blackDuckScanFreestyle.setPolaris_assessment_types("SCA");
        blackDuckScanFreestyle.setPolaris_branch_name("test");
        blackDuckScanFreestyle.setPolaris_sast_build_command("mvn clean install");
        blackDuckScanFreestyle.setPolaris_sast_clean_command("mvn clean install");
        blackDuckScanFreestyle.setPolaris_sast_config_path("fake/path/config.yml");
        blackDuckScanFreestyle.setPolaris_sast_args("--o");
        blackDuckScanFreestyle.setPolaris_sca_search_depth(2);
        blackDuckScanFreestyle.setPolaris_sca_config_path("fake/path/application.properties");
        blackDuckScanFreestyle.setPolaris_sca_args("--o");

        Map<String, Object> polarisParametersMap =
                ParameterMappingService.preparePolarisParametersMap(blackDuckScanFreestyle);

        assertEquals(13, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("mvn clean install", polarisParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("mvn clean install", polarisParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake/path/config.yml", polarisParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", polarisParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));
        assertEquals(2, polarisParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/path/application.properties",
                polarisParametersMap.get(ApplicationConstants.DETECT_CONFIG_PATH_KEY));
        assertEquals("--o", polarisParametersMap.get(ApplicationConstants.DETECT_ARGS_KEY));
    }

    @Test
    public void prepareSRMParametersMapTestForMultibranchTest() {
        blackDuckScanStep.setSrm_url("https://fake.srm-url");
        blackDuckScanStep.setSrm_apikey("fake-api-key");
        blackDuckScanStep.setSrm_assessment_types("SCA");
        blackDuckScanStep.setSrm_project_name("test-project");
        blackDuckScanStep.setSrm_project_id("fake-id");
        blackDuckScanStep.setSrm_branch_name("test");
        blackDuckScanStep.setSrm_branch_parent("main");
        blackDuckScanStep.setDetect_execution_path("/fake/path/bd");
        blackDuckScanStep.setCoverity_execution_path("/fake/path/cov");

        Map<String, Object> srmParametersMap = ParameterMappingService.prepareSrmParametersMap(blackDuckScanStep);

        assertEquals(9, srmParametersMap.size());
        assertEquals("https://fake.srm-url", srmParametersMap.get(ApplicationConstants.SRM_URL_KEY));
        assertEquals("fake-api-key", srmParametersMap.get(ApplicationConstants.SRM_APIKEY_KEY));
        assertEquals("SCA", srmParametersMap.get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY));
        assertEquals("test-project", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_NAME_KEY));
        assertEquals("fake-id", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_ID_KEY));
        assertEquals("test", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_NAME_KEY));
        assertEquals("main", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_PARENT_KEY));
        assertEquals("/fake/path/bd", srmParametersMap.get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY));
        assertEquals("/fake/path/cov", srmParametersMap.get(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY));

        Map<String, Object> emptySrmParametersMap =
                ParameterMappingService.prepareSrmParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptySrmParametersMap.size());
    }

    @Test
    public void prepareSRMParametersMapTestsMapForFreestyleTest() {
        blackDuckScanFreestyle.setSrm_url("https://fake.srm-url");
        blackDuckScanFreestyle.setSrm_apikey("fake-api-key");
        blackDuckScanFreestyle.setSrm_assessment_types("SCA");
        blackDuckScanFreestyle.setSrm_project_name("test-project");
        blackDuckScanFreestyle.setSrm_project_id("fake-id");
        blackDuckScanFreestyle.setSrm_branch_name("test");
        blackDuckScanFreestyle.setSrm_branch_parent("main");
        blackDuckScanFreestyle.setDetect_execution_path("/fake/path/bd");
        blackDuckScanFreestyle.setCoverity_execution_path("/fake/path/cov");
        blackDuckScanFreestyle.setSrm_sast_build_command("mvn clean install");
        blackDuckScanFreestyle.setSrm_sast_clean_command("mvn clean install");
        blackDuckScanFreestyle.setSrm_sast_config_path("fake/path/config.yml");
        blackDuckScanFreestyle.setSrm_sast_args("--o");
        blackDuckScanFreestyle.setSrm_sca_search_depth(2);
        blackDuckScanFreestyle.setSrm_sca_config_path("fake/path/application.properties");
        blackDuckScanFreestyle.setSrm_sca_args("--o");

        Map<String, Object> srmParametersMap = ParameterMappingService.prepareSrmParametersMap(blackDuckScanFreestyle);

        assertEquals(16, srmParametersMap.size());
        assertEquals("https://fake.srm-url", srmParametersMap.get(ApplicationConstants.SRM_URL_KEY));
        assertEquals("fake-api-key", srmParametersMap.get(ApplicationConstants.SRM_APIKEY_KEY));
        assertEquals("SCA", srmParametersMap.get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY));
        assertEquals("test-project", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_NAME_KEY));
        assertEquals("fake-id", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_ID_KEY));
        assertEquals("test", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_NAME_KEY));
        assertEquals("main", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_PARENT_KEY));
        assertEquals("/fake/path/bd", srmParametersMap.get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY));
        assertEquals("/fake/path/cov", srmParametersMap.get(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY));
        assertEquals("mvn clean install", srmParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("mvn clean install", srmParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake/path/config.yml", srmParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", srmParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));
        assertEquals(2, srmParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));

        Map<String, Object> emptySrmParametersMap =
                ParameterMappingService.prepareSrmParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptySrmParametersMap.size());
    }

    @Test
    public void prepareSarifReportParametersMap() {
        blackDuckScanStep.setBlackducksca_reports_sarif_create(true);
        blackDuckScanStep.setBlackducksca_reports_sarif_file_path("/fake/path");
        blackDuckScanStep.setBlackducksca_reports_sarif_severities("CRITICAL");
        blackDuckScanStep.setBlackducksca_reports_sarif_groupSCAIssues(true);

        Map<String, Object> sarifParametersMap =
                ParameterMappingService.prepareSarifReportParametersMap(blackDuckScanStep);

        assertEquals(4, sarifParametersMap.size());
        assertTrue((boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY));
        assertEquals(
                "/fake/path", sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY));
        assertEquals(
                "CRITICAL", sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY));
        assertTrue(
                (boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY));

        Map<String, Object> emptySarifParametersMap =
                ParameterMappingService.prepareSarifReportParametersMap(new BlackDuckScanStep());

        assertEquals(0, emptySarifParametersMap.size());
    }

    @Test
    public void getBridgeDownloadUrlBasedOnAgentOSTest() {
        String downloadUrlLinux = "https://fake-url.com/linux";
        String downloadUrlMac = "https://fake-url.com/mac";
        String downloadUrlWindows = "https://fake-url.com/windows";

        String os = System.getProperty("os.name").toLowerCase();
        String agentSpecificDownloadUrl = ParameterMappingService.getBridgeDownloadUrlBasedOnAgentOS(
                workspace, listenerMock, downloadUrlMac, downloadUrlLinux, downloadUrlWindows);

        if (os.contains("linux")) {
            assertEquals(downloadUrlLinux, agentSpecificDownloadUrl);
        } else if (os.contains("mac")) {
            assertEquals(downloadUrlMac, agentSpecificDownloadUrl);
        } else {
            assertEquals(downloadUrlWindows, agentSpecificDownloadUrl);
        }
    }

    @Test
    public void validateProductTest() {
        assertTrue(ParameterMappingService.validateProduct("blackduck", listenerMock));
        assertTrue(ParameterMappingService.validateProduct("blackducksca", listenerMock));
        assertTrue(ParameterMappingService.validateProduct("POLARIS", listenerMock));
        assertTrue(ParameterMappingService.validateProduct("COveRiTy", listenerMock));
        assertFalse(ParameterMappingService.validateProduct("polar1s", listenerMock));
        assertTrue(ParameterMappingService.validateProduct("sRm", listenerMock));
        assertTrue(ParameterMappingService.validateProduct("SRM", listenerMock));
    }

    @Test
    public void getBuildResultIfIssuesAreFoundTest() {
        LoggerWrapper loggerMock = new LoggerWrapper(listenerMock);

        assertEquals(
                ParameterMappingService.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "FAILURE", loggerMock),
                Result.FAILURE);
        assertEquals(
                ParameterMappingService.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "UNSTABLE", loggerMock),
                Result.UNSTABLE);
        assertEquals(
                ParameterMappingService.getBuildResultIfIssuesAreFound(
                        ErrorCode.BRIDGE_BUILD_BREAK, "SUCCESS", loggerMock),
                Result.SUCCESS);
        assertNull(ParameterMappingService.getBuildResultIfIssuesAreFound(
                ErrorCode.BRIDGE_BUILD_BREAK, "ABORTED", loggerMock));
        assertNull(ParameterMappingService.getBuildResultIfIssuesAreFound(
                ErrorCode.BRIDGE_ADAPTER_ERROR, "UNSTABLE", loggerMock));
    }

    @Test
    public void getSecurityProductItemsTest() {
        ListBoxModel items = ParameterMappingService.getSecurityProductItems();

        assertEquals(4, items.size());

        assertEquals(SecurityProduct.BLACKDUCKSCA.getProductLabel(), items.get(0).name);
        assertEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase(), items.get(0).value);

        assertEquals(SecurityProduct.COVERITY.getProductLabel(), items.get(1).name);
        assertEquals(SecurityProduct.COVERITY.name().toLowerCase(), items.get(1).value);

        assertEquals(SecurityProduct.POLARIS.getProductLabel(), items.get(2).name);
        assertEquals(SecurityProduct.POLARIS.name().toLowerCase(), items.get(2).value);

        assertEquals(SecurityProduct.SRM.getProductLabel(), items.get(3).name);
        assertEquals(SecurityProduct.SRM.name().toLowerCase(), items.get(3).value);
    }

    @Test
    public void getMarkBuildStatusItemsTest() {
        ListBoxModel items = ParameterMappingService.getMarkBuildStatusItems();

        assertEquals(3, items.size());

        assertEquals(BuildStatus.FAILURE.name(), items.get(0).name);
        assertEquals(BuildStatus.FAILURE.name(), items.get(0).value);

        assertEquals(BuildStatus.UNSTABLE.name(), items.get(1).name);
        assertEquals(BuildStatus.UNSTABLE.name(), items.get(1).value);

        assertEquals(BuildStatus.SUCCESS.name(), items.get(2).name);
        assertEquals(BuildStatus.SUCCESS.name(), items.get(2).value);
    }
}
