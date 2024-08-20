package io.jenkins.plugins.security.scan.factory;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.security.scan.PluginParametersHandler;
import io.jenkins.plugins.security.scan.SecurityScanner;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.extension.SecurityScan;
import io.jenkins.plugins.security.scan.extension.freestyle.FreestyleScan;
import io.jenkins.plugins.security.scan.extension.global.ScannerGlobalConfig;
import io.jenkins.plugins.security.scan.extension.pipeline.PrCommentScan;
import io.jenkins.plugins.security.scan.extension.pipeline.ReturnStatusScan;
import io.jenkins.plugins.security.scan.global.*;
import io.jenkins.plugins.security.scan.global.enums.BuildStatus;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.ScannerArgumentService;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import jenkins.model.GlobalConfiguration;

public class ScanParametersFactory {
    public static PluginParametersHandler createPipelineCommand(
            Run<?, ?> run, TaskListener listener, EnvVars envVars, Launcher launcher, Node node, FilePath workspace) {
        return new PluginParametersHandler(
                new SecurityScanner(
                        run,
                        listener,
                        launcher,
                        workspace,
                        envVars,
                        new ScannerArgumentService(listener, envVars, workspace)),
                workspace,
                envVars,
                listener);
    }

    public static Map<String, Object> preparePipelineParametersMap(
            SecurityScan securityScan, Map<String, Object> parametersMap, TaskListener listener)
            throws PluginExceptionHandler {
        String product = securityScan.getProduct();

        if (validateProduct(product, listener)) {
            parametersMap.put(
                    ApplicationConstants.PRODUCT_KEY,
                    securityScan.getProduct().trim().toUpperCase());

            parametersMap.putAll(prepareCoverityParametersMap(securityScan));
            parametersMap.putAll(preparePolarisParametersMap(securityScan));
            parametersMap.putAll(prepareBlackDuckParametersMap(securityScan));
            parametersMap.putAll(prepareSrmParametersMap(securityScan));
            parametersMap.putAll(prepareSarifReportParametersMap(securityScan));

            if (!Utility.isStringNullOrBlank(securityScan.getBitbucket_username())) {
                parametersMap.put(ApplicationConstants.BITBUCKET_USERNAME_KEY, securityScan.getBitbucket_username());
            }
            if (!Utility.isStringNullOrBlank(securityScan.getBitbucket_token())) {
                parametersMap.put(ApplicationConstants.BITBUCKET_TOKEN_KEY, securityScan.getBitbucket_token());
            }
            if (!Utility.isStringNullOrBlank(securityScan.getGitlab_token())) {
                parametersMap.put(ApplicationConstants.GITLAB_TOKEN_KEY, securityScan.getGitlab_token());
            }

            if (!Utility.isStringNullOrBlank(securityScan.getGithub_token())) {
                parametersMap.put(ApplicationConstants.GITHUB_TOKEN_KEY, securityScan.getGithub_token());
            }

            parametersMap.putAll(prepareAddtionalParametersMap(securityScan));

            if (securityScan instanceof ReturnStatusScan) {
                ReturnStatusScan returnStatusScan = (ReturnStatusScan) securityScan;
                if (returnStatusScan.isReturn_status() != null) {
                    parametersMap.put(ApplicationConstants.RETURN_STATUS_KEY, returnStatusScan.isReturn_status());
                }
            }

            return parametersMap;
        } else {
            throw new PluginExceptionHandler(ErrorCode.INVALID_SECURITY_PRODUCT);
        }
    }

    public static Map<String, Object> getGlobalConfigurationValues(FilePath workspace, TaskListener listener) {
        Map<String, Object> globalParameters = new HashMap<>();
        ScannerGlobalConfig config = GlobalConfiguration.all().get(ScannerGlobalConfig.class);

        ScanCredentialsHelper scanCredentialsHelper = new ScanCredentialsHelper();

        if (config != null) {
            String bridgeDownloadUrl = getBridgeDownloadUrlBasedOnAgentOS(
                    workspace,
                    listener,
                    config.getBridgeDownloadUrlForMac(),
                    config.getBridgeDownloadUrlForLinux(),
                    config.getBridgeDownloadUrlForWindows());

            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.BLACKDUCKSCA_URL_KEY, config.getBlackDuckSCAUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getBlackDuckSCACredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY,
                    config.getDetectInstallationPath());
            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.COVERITY_URL_KEY, config.getCoverityConnectUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_USER_KEY,
                    scanCredentialsHelper
                            .getUsernameByCredentialsId(config.getCoverityCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_PASSPHRASE_KEY,
                    scanCredentialsHelper
                            .getPasswordByCredentialsId(config.getCoverityCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY,
                    config.getCoverityInstallationPath());
            addParameterIfNotBlank(globalParameters, ApplicationConstants.SRM_URL_KEY, config.getSrmUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.SRM_APIKEY_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getSrmCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.SRM_SCA_DETECT_EXECUTION_PATH_KEY,
                    config.getSrmSCAInstallationPath());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.SRM_SAST_EXECUTION_PATH_KEY,
                    config.getSrmSASTInstallationPath());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BITBUCKET_USERNAME_KEY,
                    scanCredentialsHelper
                            .getUsernameByCredentialsId(config.getBitbucketCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BITBUCKET_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getBitbucketCredentialsId())
                            .orElse(scanCredentialsHelper
                                    .getPasswordByCredentialsId(config.getBitbucketCredentialsId())
                                    .orElse(null)));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.GITHUB_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getGithubCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.GITLAB_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getGitlabCredentialsId())
                            .orElse(null));
            addParameterIfNotBlank(globalParameters, ApplicationConstants.BRIDGECLI_DOWNLOAD_URL, bridgeDownloadUrl);
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY,
                    config.getBridgeInstallationPath());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION,
                    config.getBridgeDownloadVersion());
            addParameterIfNotBlank(
                    globalParameters, ApplicationConstants.POLARIS_SERVER_URL_KEY, config.getPolarisServerUrl());
            addParameterIfNotBlank(
                    globalParameters,
                    ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                    scanCredentialsHelper
                            .getApiTokenByCredentialsId(config.getPolarisCredentialsId())
                            .orElse(null));
        }

        return globalParameters;
    }

    public static void addParameterIfNotBlank(Map<String, Object> parameters, String key, String value) {
        if (!Utility.isStringNullOrBlank(value)) {
            parameters.put(key, value);
        }
    }

    public static void addParameterIfNotBlank(Map<String, Object> parameters, String key, Integer value) {
        if (value != null) {
            parameters.put(key, value);
        }
    }

    public static void addParameterIfNotBlank(Map<String, Object> parameters, String key, Boolean value) {
        if (value != null) {
            parameters.put(key, value);
        }
    }

    public static Map<String, Object> prepareBlackDuckParametersMap(SecurityScan securityScan) {
        Map<String, Object> blackDuckParameters = new HashMap<>();

        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_URL_KEY, securityScan.getBlackduck_url());
        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_URL_KEY, securityScan.getBlackducksca_url());

        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, securityScan.getBlackduck_token());
        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_TOKEN_KEY, securityScan.getBlackducksca_token());

        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY,
                securityScan.getBlackduck_install_directory());
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY,
                securityScan.getDetect_install_directory());

        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY,
                securityScan.getBlackduck_scan_failure_severities());
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY,
                securityScan.getBlackducksca_scan_failure_severities());

        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.DETECT_SCAN_FULL_KEY,
                securityScan.isBlackduckIntelligentScan());
        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.DETECT_SCAN_FULL_KEY, securityScan.isDetectIntelligentScan());

        if (securityScan instanceof PrCommentScan) {
            PrCommentScan prCommentScan = (PrCommentScan) securityScan;
            addParameterIfNotBlank(
                    blackDuckParameters,
                    ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY,
                    prCommentScan.isBlackduck_automation_prcomment_actualValue());
            addParameterIfNotBlank(
                    blackDuckParameters,
                    ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY,
                    prCommentScan.isBlackduck_prComment_enabled_actualValue());
            addParameterIfNotBlank(
                    blackDuckParameters,
                    ApplicationConstants.BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY,
                    prCommentScan.isBlackducksca_prComment_enabled_actualValue());
        }

        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_DOWNLOAD_URL_KEY,
                securityScan.getBlackduck_download_url());
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_DOWNLOAD_URL_KEY,
                securityScan.getBlackducksca_download_url());

        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.PROJECT_DIRECTORY_KEY, securityScan.getProject_directory());

        prepareBlackDuckToolConfigurationParametersMap(blackDuckParameters, securityScan);

        return blackDuckParameters;
    }

    public static Map<String, Object> prepareCoverityParametersMap(SecurityScan securityScan) {
        Map<String, Object> coverityParameters = new HashMap<>();

        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.COVERITY_URL_KEY, securityScan.getCoverity_url());
        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.COVERITY_USER_KEY, securityScan.getCoverity_user());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_PASSPHRASE_KEY,
                securityScan.getCoverity_passphrase());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_PROJECT_NAME_KEY,
                securityScan.getCoverity_project_name());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_STREAM_NAME_KEY,
                securityScan.getCoverity_stream_name());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_POLICY_VIEW_KEY,
                securityScan.getCoverity_policy_view());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_INSTALL_DIRECTORY_KEY,
                securityScan.getCoverity_install_directory());
        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.COVERITY_VERSION_KEY, securityScan.getCoverity_version());
        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.COVERITY_LOCAL_KEY, securityScan.isCoverity_local());
        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.PROJECT_DIRECTORY_KEY, securityScan.getProject_directory());

        if (securityScan instanceof PrCommentScan) {
            PrCommentScan prCommentScan = (PrCommentScan) securityScan;
            addParameterIfNotBlank(
                    coverityParameters,
                    ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY,
                    prCommentScan.isCoverity_automation_prcomment_actualValue());
            addParameterIfNotBlank(
                    coverityParameters,
                    ApplicationConstants.COVERITY_PRCOMMENT_ENABLED_KEY,
                    prCommentScan.isCoverity_prComment_enabled_actualValue());
        }

        prepareCoverityToolConfigurationParametersMap(coverityParameters, securityScan);

        return coverityParameters;
    }

    public static Map<String, Object> preparePolarisParametersMap(SecurityScan securityScan) {
        Map<String, Object> polarisParametersMap = new HashMap<>();

        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_SERVER_URL_KEY,
                securityScan.getPolaris_server_url());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_ACCESS_TOKEN_KEY,
                securityScan.getPolaris_access_token());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_APPLICATION_NAME_KEY,
                securityScan.getPolaris_application_name());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_PROJECT_NAME_KEY,
                securityScan.getPolaris_project_name());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_ASSESSMENT_TYPES_KEY,
                securityScan.getPolaris_assessment_types());
        addParameterIfNotBlank(
                polarisParametersMap, ApplicationConstants.POLARIS_TRIAGE_KEY, securityScan.getPolaris_triage());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_BRANCH_NAME_KEY,
                securityScan.getPolaris_branch_name());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_BRANCH_PARENT_NAME_KEY,
                securityScan.getPolaris_branch_parent_name());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_PRCOMMENT_SEVERITIES_KEY,
                securityScan.getPolaris_prComment_severities());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_TEST_SCA_TYPE_KEY,
                securityScan.getPolaris_test_sca_type());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.POLARIS_ASSESSMENT_MODE_KEY,
                securityScan.getPolaris_assessment_mode());
        addParameterIfNotBlank(
                polarisParametersMap, ApplicationConstants.PROJECT_DIRECTORY_KEY, securityScan.getProject_directory());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.PROJECT_SOURCE_ARCHIVE_KEY,
                securityScan.getProject_source_archive());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.PROJECT_SOURCE_EXCLUDES_KEY,
                securityScan.getProject_source_excludes());

        if (securityScan.isProject_source_preserveSymLinks_actualValue() != null) {
            polarisParametersMap.put(
                    ApplicationConstants.PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY,
                    securityScan.isProject_source_preserveSymLinks_actualValue());
        }

        if (securityScan instanceof PrCommentScan) {
            PrCommentScan prCommentScan = (PrCommentScan) securityScan;
            if (prCommentScan.isPolaris_prComment_enabled_actualValue() != null) {
                polarisParametersMap.put(
                        ApplicationConstants.POLARIS_PRCOMMENT_ENABLED_KEY,
                        prCommentScan.isPolaris_prComment_enabled_actualValue());
            }
        }

        if (securityScan instanceof FreestyleScan) {
            FreestyleScan freestyleScan = (FreestyleScan) securityScan;
            preparePolarisToolConfigurationParametersMap(polarisParametersMap, freestyleScan);
        }

        return polarisParametersMap;
    }

    public static Map<String, Object> prepareSrmParametersMap(SecurityScan securityScan) {
        Map<String, Object> srmParametersMap = new HashMap<>();

        addParameterIfNotBlank(srmParametersMap, ApplicationConstants.SRM_URL_KEY, securityScan.getSrm_url());
        addParameterIfNotBlank(srmParametersMap, ApplicationConstants.SRM_APIKEY_KEY, securityScan.getSrm_apikey());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.SRM_ASSESSMENT_TYPES_KEY,
                securityScan.getSrm_assessment_types());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.SRM_PROJECT_NAME_KEY, securityScan.getSrm_project_name());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.SRM_PROJECT_ID_KEY, securityScan.getSrm_project_id());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.SRM_BRANCH_NAME_KEY, securityScan.getSrm_branch_name());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.SRM_BRANCH_PARENT_KEY, securityScan.getSrm_branch_parent());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.SRM_SCA_DETECT_EXECUTION_PATH_KEY,
                securityScan.getBlackduck_execution_path());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.SRM_SCA_DETECT_EXECUTION_PATH_KEY,
                securityScan.getDetect_execution_path());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.SRM_SAST_EXECUTION_PATH_KEY,
                securityScan.getCoverity_execution_path());

        if (securityScan instanceof FreestyleScan) {
            FreestyleScan freestyleScan = (FreestyleScan) securityScan;
            prepareSrmToolConfigurationParametersMap(srmParametersMap, freestyleScan);
        }

        return srmParametersMap;
    }

    private static void prepareCoverityToolConfigurationParametersMap(
            Map<String, Object> coverityParameters, SecurityScan securityScan) {
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_BUILD_COMMAND_KEY,
                securityScan.getCoverity_build_command());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY,
                securityScan.getCoverity_clean_command());
        addParameterIfNotBlank(
                coverityParameters,
                ApplicationConstants.COVERITY_CONFIG_PATH_KEY,
                securityScan.getCoverity_config_path());
        addParameterIfNotBlank(
                coverityParameters, ApplicationConstants.COVERITY_ARGS_KEY, securityScan.getCoverity_args());
    }

    private static void prepareBlackDuckToolConfigurationParametersMap(
            Map<String, Object> blackDuckParameters, SecurityScan securityScan) {
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY,
                securityScan.getBlackduck_search_depth());
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY,
                securityScan.getBlackducksca_search_depth());

        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY,
                securityScan.getBlackduck_config_path());
        addParameterIfNotBlank(
                blackDuckParameters,
                ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY,
                securityScan.getBlackducksca_config_path());

        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_ARGS_KEY, securityScan.getBlackduck_args());
        addParameterIfNotBlank(
                blackDuckParameters, ApplicationConstants.BLACKDUCKSCA_ARGS_KEY, securityScan.getBlackducksca_args());
    }

    private static void preparePolarisToolConfigurationParametersMap(
            Map<String, Object> polarisParametersMap, FreestyleScan freestyleScan) {
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY,
                freestyleScan.getPolaris_sca_search_depth());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY,
                freestyleScan.getPolaris_sca_config_path());
        addParameterIfNotBlank(
                polarisParametersMap, ApplicationConstants.BLACKDUCKSCA_ARGS_KEY, freestyleScan.getPolaris_sca_args());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.COVERITY_BUILD_COMMAND_KEY,
                freestyleScan.getPolaris_sast_build_command());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY,
                freestyleScan.getPolaris_sast_clean_command());
        addParameterIfNotBlank(
                polarisParametersMap,
                ApplicationConstants.COVERITY_CONFIG_PATH_KEY,
                freestyleScan.getPolaris_sast_config_path());
        addParameterIfNotBlank(
                polarisParametersMap, ApplicationConstants.COVERITY_ARGS_KEY, freestyleScan.getPolaris_sast_args());
    }

    private static void prepareSrmToolConfigurationParametersMap(
            Map<String, Object> srmParametersMap, FreestyleScan freestyleScan) {
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.BLACKDUCKSCA_SEARCH_DEPTH_KEY,
                freestyleScan.getSrm_sca_search_depth());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.BLACKDUCKSCA_CONFIG_PATH_KEY,
                freestyleScan.getSrm_sca_config_path());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.BLACKDUCKSCA_ARGS_KEY, freestyleScan.getSrm_sca_args());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.COVERITY_BUILD_COMMAND_KEY,
                freestyleScan.getSrm_sast_build_command());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.COVERITY_CLEAN_COMMAND_KEY,
                freestyleScan.getSrm_sast_clean_command());
        addParameterIfNotBlank(
                srmParametersMap,
                ApplicationConstants.COVERITY_CONFIG_PATH_KEY,
                freestyleScan.getSrm_sast_config_path());
        addParameterIfNotBlank(
                srmParametersMap, ApplicationConstants.COVERITY_ARGS_KEY, freestyleScan.getSrm_sast_args());
    }

    public static Map<String, Object> prepareAddtionalParametersMap(SecurityScan securityScan) {
        Map<String, Object> bridgeParameters = new HashMap<>();

        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_DOWNLOAD_URL,
                securityScan.getSynopsys_bridge_download_url());
        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_DOWNLOAD_URL,
                securityScan.getBridgecli_download_url());
        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION,
                securityScan.getSynopsys_bridge_download_version());
        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_DOWNLOAD_VERSION,
                securityScan.getBridgecli_download_version());
        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY,
                securityScan.getSynopsys_bridge_install_directory());
        addParameterIfNotBlank(
                bridgeParameters,
                ApplicationConstants.BRIDGECLI_INSTALL_DIRECTORY,
                securityScan.getBridgecli_install_directory());

        addParameterIfNotBlank(
                bridgeParameters, ApplicationConstants.INCLUDE_DIAGNOSTICS_KEY, securityScan.isInclude_diagnostics());
        addParameterIfNotBlank(
                bridgeParameters, ApplicationConstants.NETWORK_AIRGAP_KEY, securityScan.isNetwork_airgap());
        addParameterIfNotBlank(
                bridgeParameters, ApplicationConstants.MARK_BUILD_STATUS, securityScan.getMark_build_status());

        return bridgeParameters;
    }

    public static Map<String, Object> prepareSarifReportParametersMap(SecurityScan securityScan) {
        Map<String, Object> sarifParameters = new HashMap<>();

        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY,
                securityScan.isBlackduck_reports_sarif_create());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY,
                securityScan.isBlackducksca_reports_sarif_create());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY,
                securityScan.getBlackduck_reports_sarif_file_path());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY,
                securityScan.getBlackducksca_reports_sarif_file_path());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY,
                securityScan.isBlackduck_reports_sarif_groupSCAIssues_temporary());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY,
                securityScan.isBlackducksca_reports_sarif_groupSCAIssues_temporary());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY,
                securityScan.getBlackduck_reports_sarif_severities());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY,
                securityScan.getBlackducksca_reports_sarif_severities());

        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.POLARIS_REPORTS_SARIF_CREATE_KEY,
                securityScan.isPolaris_reports_sarif_create());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.POLARIS_REPORTS_SARIF_FILE_PATH_KEY,
                securityScan.getPolaris_reports_sarif_file_path());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY,
                securityScan.isPolaris_reports_sarif_groupSCAIssues_temporary());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.POLARIS_REPORTS_SARIF_SEVERITIES_KEY,
                securityScan.getPolaris_reports_sarif_severities());
        addParameterIfNotBlank(
                sarifParameters,
                ApplicationConstants.POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY,
                securityScan.getPolaris_reports_sarif_issue_types());

        return sarifParameters;
    }

    public static String getBridgeDownloadUrlBasedOnAgentOS(
            FilePath workspace,
            TaskListener listener,
            String bridgeDownloadUrlForMac,
            String bridgeDownloadUrlForLinux,
            String bridgeDownloadUrlForWindows) {
        String agentOs = Utility.getAgentOs(workspace, listener);
        if (agentOs.contains("mac")) {
            return bridgeDownloadUrlForMac;
        } else if (agentOs.contains("linux")) {
            return bridgeDownloadUrlForLinux;
        } else {
            return bridgeDownloadUrlForWindows;
        }
    }

    public static boolean validateProduct(String product, TaskListener listener) {
        LoggerWrapper logger = new LoggerWrapper(listener);

        boolean isValid = !Utility.isStringNullOrBlank(product)
                && Arrays.stream(product.split(","))
                        .map(String::trim)
                        .map(String::toUpperCase)
                        .allMatch(p -> p.equals(SecurityProduct.BLACKDUCK.name())
                                || p.equals(SecurityProduct.POLARIS.name())
                                || p.equals(SecurityProduct.COVERITY.name())
                                || p.equals(SecurityProduct.SRM.name()));

        if (!isValid) {
            logger.error("Invalid Security Product");
            logger.info("Supported values for security products: " + Arrays.toString(SecurityProduct.values()));
        }

        return isValid;
    }

    public static Result getBuildResultIfIssuesAreFound(
            int exitCode, String markBuildIfIssuesArePresent, LoggerWrapper logger) {
        Result result = null;

        if (exitCode == ErrorCode.BRIDGE_BUILD_BREAK && !Utility.isStringNullOrBlank((markBuildIfIssuesArePresent))) {
            try {
                BuildStatus buildStatus = BuildStatus.valueOf(markBuildIfIssuesArePresent.toUpperCase());
                if (buildStatus.in(BuildStatus.FAILURE, BuildStatus.UNSTABLE, BuildStatus.SUCCESS)) {
                    result = Utility.getMappedResultForBuildStatus(buildStatus);
                }
            } catch (IllegalArgumentException e) {
                logger.warn("Unsupported value for " + ApplicationConstants.MARK_BUILD_STATUS
                        + ": " + markBuildIfIssuesArePresent
                        + ". Supported values are: "
                        + Arrays.asList(BuildStatus.values()));
            }
        }

        return result;
    }

    public static ListBoxModel getSecurityProductItems() {
        ListBoxModel items = new ListBoxModel();
        items.add(
                SecurityProduct.BLACKDUCKSCA.getProductLabel(),
                SecurityProduct.BLACKDUCKSCA.name().toLowerCase());
        items.add(
                SecurityProduct.COVERITY.getProductLabel(),
                SecurityProduct.COVERITY.name().toLowerCase());
        items.add(
                SecurityProduct.POLARIS.getProductLabel(),
                SecurityProduct.POLARIS.name().toLowerCase());
        items.add(
                SecurityProduct.SRM.getProductLabel(),
                SecurityProduct.SRM.name().toLowerCase());
        return items;
    }

    public static ListBoxModel getMarkBuildStatusItems() {
        ListBoxModel items = new ListBoxModel();
        items.add(BuildStatus.FAILURE.name(), BuildStatus.FAILURE.name());
        items.add(BuildStatus.UNSTABLE.name(), BuildStatus.UNSTABLE.name());
        items.add(BuildStatus.SUCCESS.name(), BuildStatus.SUCCESS.name());
        return items;
    }
}
