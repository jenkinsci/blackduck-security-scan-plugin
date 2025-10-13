package io.jenkins.plugins.security.scan.service;

import static org.junit.jupiter.api.Assertions.*;

import hudson.FilePath;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.extension.freestyle.SecurityScanFreestyle;
import io.jenkins.plugins.security.scan.extension.pipeline.SecurityScanStep;
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
    private SecurityScanStep securityScanStep;
    private SecurityScanFreestyle securityScanFreestyle;

    @BeforeEach
    public void setUp() {
        workspace = new FilePath(new File(System.getProperty("user.home")));
        listenerMock = Mockito.mock(TaskListener.class);
        securityScanStep = new SecurityScanStep();
        securityScanFreestyle = new SecurityScanFreestyle();
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

        securityScanStep.setProduct("BLACKDUCKSCA");
        securityScanStep.setBitbucket_token("FAKETOKEN");
        securityScanStep.setGithub_token("faketoken-github");
        securityScanStep.setGitlab_token("fakeTokeN-gItlAb");
        globalConfigValues.put(ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://fake-blackduck.url");
        globalConfigValues.put(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "fake-blackduck-token");
        globalConfigValues.put(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY, "/fake/path");

        Map<String, Object> result = ParameterMappingService.preparePipelineParametersMap(
                securityScanStep, globalConfigValues, listenerMock);

        assertEquals(8, result.size());
        assertEquals("BLACKDUCKSCA", result.get(ApplicationConstants.PRODUCT_KEY));
        assertEquals("fake-blackduck-token", result.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", result.get(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY));
        assertEquals("FAKETOKEN", result.get(ApplicationConstants.BITBUCKET_TOKEN_KEY));
        assertEquals("faketoken-github", result.get(ApplicationConstants.GITHUB_TOKEN_KEY));
        assertEquals("fakeTokeN-gItlAb", result.get(ApplicationConstants.GITLAB_TOKEN_KEY));

        securityScanStep.setProduct("invalid-product");

        assertThrows(
                PluginExceptionHandler.class,
                () -> ParameterMappingService.preparePipelineParametersMap(
                        securityScanStep, globalConfigValues, listenerMock));
    }

    @Test
    public void prepareBlackDuckSCAParametersMapTestForMultibranchTest() {
        securityScanStep.setBlackducksca_url("https://fake.blackduck-url");
        securityScanStep.setBlackducksca_token("fake-token");
        securityScanStep.setDetect_install_directory("/fake/path");
        securityScanStep.setBlackducksca_scan_full(true);
        securityScanStep.setBlackducksca_prComment_enabled(true);
        securityScanStep.setBlackducksca_fixpr_enabled(true);
        securityScanStep.setBlackducksca_fixpr_filter_severities("CRITICAL");
        securityScanStep.setBlackducksca_fixpr_useUpgradeGuidance("SHORT_TERM");
        securityScanStep.setBlackducksca_fixpr_maxCount(1);
        securityScanStep.setDetect_download_url("https://fake.blackduck-download-url");
        securityScanStep.setBlackducksca_scan_failure_severities("MAJOR");
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setBlackducksca_waitForScan(true);
        securityScanStep.setDetect_search_depth(2);
        securityScanStep.setDetect_config_path("fake/directory/application.properties");
        securityScanStep.setDetect_args("--o");

        Map<String, Object> blackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckSCAParametersMap(securityScanStep);

        assertEquals(16, blackDuckParametersMap.size());
        assertEquals(
                "https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FULL_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_ENABLED_KEY));
        assertEquals(
                "SHORT_TERM",
                blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_USEUPGRADEGUIDANCE_KEY));
        assertEquals(
                "CRITICAL", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_FILTER_SEVERITIES_KEY));
        assertEquals(1, blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_FIXPR_MAXCOUNT_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY));
        assertEquals(
                "MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY));
        assertEquals("test/directory", blackDuckParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertTrue((Boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY));
        assertEquals(2, blackDuckParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/directory/application.properties",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_CONFIG_PATH_KEY));
        assertEquals("--o", blackDuckParametersMap.get(ApplicationConstants.DETECT_ARGS_KEY));
        Map<String, Object> emptyBlackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckSCAParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBlackDuckParametersMap.size());
    }

    @Test
    public void prepareBlackDuckSCAParametersMapTestsMapForFreestyleTest() {
        securityScanFreestyle.setBlackducksca_url("https://fake.blackduck-url");
        securityScanFreestyle.setBlackducksca_token("fake-token");
        securityScanFreestyle.setDetect_install_directory("/fake/path");
        securityScanFreestyle.setBlackducksca_scan_full(true);
        securityScanFreestyle.setDetect_download_url("https://fake.blackduck-download-url");
        securityScanFreestyle.setBlackducksca_scan_failure_severities("MAJOR");
        securityScanFreestyle.setBlackducksca_waitForScan(true);
        securityScanFreestyle.setProject_directory("test/directory");
        securityScanFreestyle.setDetect_search_depth(2);
        securityScanFreestyle.setDetect_config_path("fake/directory/application.properties");
        securityScanFreestyle.setDetect_args("--o");

        Map<String, Object> blackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckSCAParametersMap(securityScanFreestyle);

        assertEquals(11, blackDuckParametersMap.size());
        assertEquals(
                "https://fake.blackduck-url", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_URL_KEY));
        assertEquals("fake-token", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY));
        assertEquals("/fake/path", blackDuckParametersMap.get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY));
        assertTrue((boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FULL_KEY));
        assertEquals(
                "https://fake.blackduck-download-url",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY));
        assertEquals(
                "MAJOR", blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY));
        assertEquals("test/directory", blackDuckParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertTrue((Boolean) blackDuckParametersMap.get(ApplicationConstants.BLACKDUCKSCA_WAITFORSCAN_KEY));
        assertEquals(2, blackDuckParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));
        assertEquals(
                "fake/directory/application.properties",
                blackDuckParametersMap.get(ApplicationConstants.DETECT_CONFIG_PATH_KEY));
        assertEquals("--o", blackDuckParametersMap.get(ApplicationConstants.DETECT_ARGS_KEY));
        Map<String, Object> emptyBlackDuckParametersMap =
                ParameterMappingService.prepareBlackDuckSCAParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBlackDuckParametersMap.size());
    }

    @Test
    public void prepareCoverityParametersMapTestForMultibranchTest() {
        securityScanStep.setCoverity_url("https://fake.coverity-url");
        securityScanStep.setCoverity_user("fake-user");
        securityScanStep.setCoverity_passphrase("fake-passphrase");
        securityScanStep.setCoverity_project_name("fake-project");
        securityScanStep.setCoverity_stream_name("fake-stream");
        securityScanStep.setCoverity_policy_view("fake-policy");
        securityScanStep.setCoverity_install_directory("/fake/path");
        securityScanStep.setCoverity_prComment_enabled(true);
        securityScanStep.setCoverity_version("1.0.0");
        securityScanStep.setCoverity_local(true);
        securityScanStep.setCoverity_waitForScan(true);
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setCoverity_build_command("fake-build-command");
        securityScanStep.setCoverity_clean_command("fake-clean-command");
        securityScanStep.setCoverity_config_path("fake-config-path");
        securityScanStep.setCoverity_args("--o");

        Map<String, Object> coverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(securityScanStep);

        assertEquals(16, coverityParametersMap.size());
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
        assertTrue((Boolean) coverityParametersMap.get(ApplicationConstants.COVERITY_WAITFORSCAN_KEY));
        assertEquals("fake-build-command", coverityParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("fake-clean-command", coverityParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake-config-path", coverityParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", coverityParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));

        Map<String, Object> emptyCoverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(new SecurityScanStep());
        assertEquals(0, emptyCoverityParametersMap.size());
    }

    @Test
    public void prepareCoverityParametersMapForFreestyleTest() {
        securityScanFreestyle.setCoverity_url("https://fake.coverity-url");
        securityScanFreestyle.setCoverity_user("fake-user");
        securityScanFreestyle.setCoverity_passphrase("fake-passphrase");
        securityScanFreestyle.setCoverity_project_name("fake-project");
        securityScanFreestyle.setCoverity_stream_name("fake-stream");
        securityScanFreestyle.setCoverity_policy_view("fake-policy");
        securityScanFreestyle.setCoverity_install_directory("/fake/path");
        securityScanFreestyle.setCoverity_version("1.0.0");
        securityScanFreestyle.setCoverity_local(true);
        securityScanFreestyle.setProject_directory("test/directory");
        securityScanFreestyle.setCoverity_waitForScan(true);
        securityScanFreestyle.setCoverity_build_command("fake-build-command");
        securityScanFreestyle.setCoverity_clean_command("fake-clean-command");
        securityScanFreestyle.setCoverity_config_path("fake-config-path");
        securityScanFreestyle.setCoverity_args("--o");

        Map<String, Object> coverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(securityScanFreestyle);

        assertEquals(15, coverityParametersMap.size());
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
        assertTrue((Boolean) coverityParametersMap.get(ApplicationConstants.COVERITY_WAITFORSCAN_KEY));
        assertEquals("fake-build-command", coverityParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("fake-clean-command", coverityParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake-config-path", coverityParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", coverityParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));

        Map<String, Object> emptyCoverityParametersMap =
                ParameterMappingService.prepareCoverityParametersMap(new SecurityScanStep());
        assertEquals(0, emptyCoverityParametersMap.size());
    }

    @Test
    public void prepareBridgeParametersMapTest() {
        securityScanStep.setBridgecli_download_url("https://fake.bridge-download.url");
        securityScanStep.setBridgecli_download_version("1.0.0");
        securityScanStep.setBridgecli_install_directory("/fake/path");
        securityScanStep.setInclude_diagnostics(true);
        securityScanStep.setNetwork_airgap(true);
        securityScanStep.setNetwork_ssl_trustAll(true);
        securityScanStep.setNetwork_ssl_cert_file("/fake/cert/file");

        Map<String, Object> bridgeParametersMap =
                ParameterMappingService.prepareAddtionalParametersMap(securityScanStep);

        assertEquals(7, bridgeParametersMap.size());
        assertEquals(
                "https://fake.bridge-download.url",
                bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_DOWNLOAD_URL));
        assertEquals("1.0.0", bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION));
        assertEquals("/fake/path", bridgeParametersMap.get(ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.NETWORK_AIRGAP_KEY));
        assertTrue((boolean) bridgeParametersMap.get(ApplicationConstants.NETWORK_SSL_TRUSTALL_KEY));
        assertEquals("/fake/cert/file", bridgeParametersMap.get(ApplicationConstants.NETWORK_SSL_CERT_FILE_KEY));

        Map<String, Object> emptyBridgeParametersMap =
                ParameterMappingService.prepareAddtionalParametersMap(new SecurityScanStep());

        assertEquals(0, emptyBridgeParametersMap.size());
    }

    @Test
    public void getproductUrlTest() {

        Map<String, Object> scanParametersMap = Map.of(
                ApplicationConstants.PRODUCT_KEY, "blackducksca",
                ApplicationConstants.BLACKDUCKSCA_URL_KEY, "https://test.blackduck.com",
                ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, "TEST_BLACKDUCKSCA_TOKEN");

        String productUrl = ParameterMappingService.getProductUrl(scanParametersMap);

        assertEquals(productUrl, scanParametersMap.get(ApplicationConstants.BLACKDUCKSCA_URL_KEY));
    }

    @Test
    public void preparePolarisParametersMapForMultibranchTest() {
        securityScanStep.setPolaris_server_url("https://fake.polaris-server.url");
        securityScanStep.setPolaris_access_token("fake-access-token");
        securityScanStep.setPolaris_application_name("fake-application-name");
        securityScanStep.setPolaris_project_name("fake-project-name");
        securityScanStep.setPolaris_assessment_types("SCA");
        securityScanStep.setPolaris_branch_name("test");
        securityScanStep.setPolaris_branch_parent_name("master");
        securityScanStep.setPolaris_prComment_enabled(true);
        securityScanStep.setPolaris_prComment_severities("high, critical");
        securityScanStep.setPolaris_waitForScan(true);
        securityScanStep.setPolaris_assessment_mode("SOURCE_UPLOAD");
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setProject_source_archive("fake-source-archive");
        securityScanStep.setProject_source_preserveSymLinks(true);
        securityScanStep.setProject_source_excludes("test_exclude");

        Map<String, Object> polarisParametersMap =
                ParameterMappingService.preparePolarisParametersMap(securityScanStep);

        assertEquals(15, polarisParametersMap.size());
        assertEquals(
                "https://fake.polaris-server.url",
                polarisParametersMap.get(ApplicationConstants.POLARIS_SERVER_URL_KEY));
        assertEquals("fake-access-token", polarisParametersMap.get(ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY));
        assertEquals("test", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_NAME_KEY));
        assertEquals("master", polarisParametersMap.get(ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY));
        assertEquals(true, polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY));
        assertEquals("high, critical", polarisParametersMap.get(ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY));
        assertTrue((Boolean) polarisParametersMap.get(ApplicationConstants.POLARIS_WAITFORSCAN_KEY));
        assertEquals("SOURCE_UPLOAD", polarisParametersMap.get(ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY));
        assertEquals("test/directory", polarisParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("fake-source-archive", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY));
        assertEquals("test_exclude", polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY));
        assertTrue((Boolean) polarisParametersMap.get(ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY));
    }

    @Test
    public void preparePolarisParametersMapForFreestyleTest() {
        securityScanFreestyle.setProduct("POLARIS");
        securityScanFreestyle.setBitbucket_token("FAKETOKEN");
        securityScanFreestyle.setGithub_token("faketoken-github");
        securityScanFreestyle.setGitlab_token("fakeTokeN-gItlAb");
        securityScanFreestyle.setPolaris_server_url("https://fake.polaris-server.url");
        securityScanFreestyle.setPolaris_access_token("fake-access-token");
        securityScanFreestyle.setPolaris_application_name("fake-application-name");
        securityScanFreestyle.setPolaris_project_name("fake-project-name");
        securityScanFreestyle.setPolaris_assessment_types("SCA");
        securityScanFreestyle.setPolaris_branch_name("test");
        securityScanFreestyle.setPolaris_sast_build_command("mvn clean install");
        securityScanFreestyle.setPolaris_sast_clean_command("mvn clean install");
        securityScanFreestyle.setPolaris_sast_config_path("fake/path/config.yml");
        securityScanFreestyle.setPolaris_sast_args("--o");
        securityScanFreestyle.setPolaris_sca_search_depth(2);
        securityScanFreestyle.setPolaris_sca_config_path("fake/path/application.properties");
        securityScanFreestyle.setPolaris_sca_args("--o");

        Map<String, Object> polarisParametersMap =
                ParameterMappingService.preparePolarisParametersMap(securityScanFreestyle);

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
        securityScanStep.setSrm_url("https://fake.srm-url");
        securityScanStep.setSrm_apikey("fake-api-key");
        securityScanStep.setSrm_assessment_types("SCA");
        securityScanStep.setSrm_project_name("test-project");
        securityScanStep.setSrm_project_id("fake-id");
        securityScanStep.setSrm_branch_name("test");
        securityScanStep.setSrm_branch_parent("main");
        securityScanStep.setDetect_execution_path("/fake/path/bd");
        securityScanStep.setSrm_waitForScan(true);
        securityScanStep.setProject_directory("test/directory");
        securityScanStep.setCoverity_execution_path("/fake/path/cov");

        Map<String, Object> srmParametersMap = ParameterMappingService.prepareSrmParametersMap(securityScanStep);

        assertEquals(11, srmParametersMap.size());
        assertEquals("https://fake.srm-url", srmParametersMap.get(ApplicationConstants.SRM_URL_KEY));
        assertEquals("fake-api-key", srmParametersMap.get(ApplicationConstants.SRM_APIKEY_KEY));
        assertEquals("SCA", srmParametersMap.get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY));
        assertEquals("test-project", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_NAME_KEY));
        assertEquals("fake-id", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_ID_KEY));
        assertEquals("test", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_NAME_KEY));
        assertEquals("main", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_PARENT_KEY));
        assertEquals("/fake/path/bd", srmParametersMap.get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY));
        assertEquals("/fake/path/cov", srmParametersMap.get(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY));
        assertTrue((Boolean) srmParametersMap.get(ApplicationConstants.SRM_WAITFORSCAN_KEY));
        assertEquals("test/directory", srmParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));

        Map<String, Object> emptySrmParametersMap =
                ParameterMappingService.prepareSrmParametersMap(new SecurityScanStep());

        assertEquals(0, emptySrmParametersMap.size());
    }

    @Test
    public void prepareSRMParametersMapTestsMapForFreestyleTest() {
        securityScanFreestyle.setSrm_url("https://fake.srm-url");
        securityScanFreestyle.setSrm_apikey("fake-api-key");
        securityScanFreestyle.setSrm_assessment_types("SCA");
        securityScanFreestyle.setSrm_project_name("test-project");
        securityScanFreestyle.setSrm_project_id("fake-id");
        securityScanFreestyle.setSrm_branch_name("test");
        securityScanFreestyle.setSrm_branch_parent("main");
        securityScanFreestyle.setDetect_execution_path("/fake/path/bd");
        securityScanFreestyle.setSrm_waitForScan(true);
        securityScanFreestyle.setProject_directory("test/directory");
        securityScanFreestyle.setCoverity_execution_path("/fake/path/cov");
        securityScanFreestyle.setSrm_sast_build_command("mvn clean install");
        securityScanFreestyle.setSrm_sast_clean_command("mvn clean install");
        securityScanFreestyle.setSrm_sast_config_path("fake/path/config.yml");
        securityScanFreestyle.setSrm_sast_args("--o");
        securityScanFreestyle.setSrm_sca_search_depth(2);
        securityScanFreestyle.setSrm_sca_config_path("fake/path/application.properties");
        securityScanFreestyle.setSrm_sca_args("--o");

        Map<String, Object> srmParametersMap = ParameterMappingService.prepareSrmParametersMap(securityScanFreestyle);

        assertEquals(18, srmParametersMap.size());
        assertEquals("https://fake.srm-url", srmParametersMap.get(ApplicationConstants.SRM_URL_KEY));
        assertEquals("fake-api-key", srmParametersMap.get(ApplicationConstants.SRM_APIKEY_KEY));
        assertEquals("SCA", srmParametersMap.get(ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY));
        assertEquals("test-project", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_NAME_KEY));
        assertEquals("fake-id", srmParametersMap.get(ApplicationConstants.SRM_PROJECT_ID_KEY));
        assertEquals("test", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_NAME_KEY));
        assertEquals("main", srmParametersMap.get(ApplicationConstants.SRM_BRANCH_PARENT_KEY));
        assertEquals("/fake/path/bd", srmParametersMap.get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY));
        assertEquals("/fake/path/cov", srmParametersMap.get(ApplicationConstants.COVERITY_EXECUTION_PATH_KEY));
        assertTrue((Boolean) srmParametersMap.get(ApplicationConstants.SRM_WAITFORSCAN_KEY));
        assertEquals("test/directory", srmParametersMap.get(ApplicationConstants.PROJECT_DIRECTORY_KEY));
        assertEquals("mvn clean install", srmParametersMap.get(ApplicationConstants.COVERITY_BUILD_COMMAND_KEY));
        assertEquals("mvn clean install", srmParametersMap.get(ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY));
        assertEquals("fake/path/config.yml", srmParametersMap.get(ApplicationConstants.COVERITY_CONFIG_PATH_KEY));
        assertEquals("--o", srmParametersMap.get(ApplicationConstants.COVERITY_ARGS_KEY));
        assertEquals(2, srmParametersMap.get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY));

        Map<String, Object> emptySrmParametersMap =
                ParameterMappingService.prepareSrmParametersMap(new SecurityScanStep());

        assertEquals(0, emptySrmParametersMap.size());
    }

    @Test
    public void prepareSarifReportParametersMap() {
        securityScanStep.setBlackducksca_reports_sarif_create(true);
        securityScanStep.setBlackducksca_reports_sarif_file_path("/fake/path");
        securityScanStep.setBlackducksca_reports_sarif_severities("CRITICAL");
        securityScanStep.setBlackducksca_reports_sarif_groupSCAIssues(true);

        Map<String, Object> sarifParametersMap =
                ParameterMappingService.prepareSarifReportParametersMap(securityScanStep);

        assertEquals(4, sarifParametersMap.size());
        assertTrue((boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY));
        assertEquals(
                "/fake/path", sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY));
        assertEquals(
                "CRITICAL", sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY));
        assertTrue(
                (boolean) sarifParametersMap.get(ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY));

        Map<String, Object> emptySarifParametersMap =
                ParameterMappingService.prepareSarifReportParametersMap(new SecurityScanStep());

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
