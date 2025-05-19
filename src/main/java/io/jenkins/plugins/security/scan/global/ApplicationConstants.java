package io.jenkins.plugins.security.scan.global;

import java.util.List;

public class ApplicationConstants {
    public static final String DISPLAY_NAME_BLACKDUCK = "Black Duck Security Scan";
    public static final String PIPELINE_STEP_NAME = "security_scan";
    public static final String BRIDGE_ARTIFACTORY_URL =
            "https://repo.blackduck.com/bds-integrations-release/com/blackduck/integration/bridge/binaries/bridge-cli-bundle";
    public static final String BRIDGE_CLI_LATEST_VERSION = "latest";
    public static final String BRIDGE_ZIP_FILE_FORMAT = "bridge-cli-bundle.zip";
    public static final String PLATFORM_LINUX = "linux64";
    public static final String PLATFORM_WINDOWS = "win64";
    public static final String PLATFORM_MAC_ARM = "macos_arm";
    public static final String PLATFORM_MACOSX = "macosx";
    public static final String MAC_ARM_COMPATIBLE_BRIDGE_VERSION = "2.1.0";
    public static final String DEFAULT_DIRECTORY_NAME = "bridge-cli-bundle";
    public static final String BRIDGE_REPORT_DIRECTORY = ".bridge";
    public static final String DEFAULT_BLACKDUCKSCA_SARIF_REPORT_LEGACY_FILE_PATH = ".bridge/Blackduck SCA SARIF Generator/";
    public static final String DEFAULT_POLARIS_SARIF_REPORT_LEGACY_FILE_PATH = ".bridge/Polaris SARIF Generator/";
    public static final String DEFAULT_BLACKDUCKSCA_SARIF_REPORT_FILE_PATH = ".blackduck/integrations/BlackduckGenerator/";
    public static final String DEFAULT_POLARIS_SARIF_REPORT_FILE_PATH = ".blackduck/integrations/PolarisSARIFGenerator/";
    public static final String POLARIS_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY = "polaris.reports.sarif.file.output";
    public static final String BLACKDUCKSCA_SCAN_INFO_SARIF_REPORT_FILE_PATH_SOURCE_KEY = "blackducksca.reports.sarif.file.output";
    public static final String SARIF_REPORT_FILENAME = "report.sarif.json";
    public static final int BRIDGE_DOWNLOAD_MAX_RETRIES = 3;
    public static final int INTERVAL_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS = 10000;
    public static final String ALL_FILES_WILDCARD_SYMBOL = "**";
    public static final String BRIDGE_CLI_EXECUTABLE = "bridge-cli";
    public static final String BRIDGE_CLI_EXECUTABLE_WINDOWS = "bridge-cli.exe";
    public static final String VERSION_FILE = "versions.txt";
    public static final String NOT_AVAILABLE = "NA";
    public static final String SCAN_INFO_OUT_FILE_NAME = ".bridge/output/scan_info_out.json";
    public static final String BLACK_DUCK_LOGO_FILE_NAME = "/plugin/blackduck-security-scan/icons/blackduck.png";

    // Jenkins Environment Variables
    public static final String ENV_JOB_NAME_KEY = "JOB_NAME";
    public static final String ENV_CHANGE_ID_KEY = "CHANGE_ID";
    public static final String ENV_CHANGE_TARGET_KEY = "CHANGE_TARGET";
    public static final String ENV_BRANCH_NAME_KEY = "BRANCH_NAME";
    public static final String ENV_CHANGE_BRANCH_KEY = "CHANGE_BRANCH";
    public static final String BRANCH_NAME = "BRANCH_NAME";
    public static final String GIT_URL = "GIT_URL";

    // Product Key
    public static final String PRODUCT_KEY = "product";

    // Blackduck Parameters (Deprecated)
    @Deprecated
    public static final String BLACKDUCK_URL_KEY = "blackduck_url";

    @Deprecated
    public static final String BLACKDUCK_TOKEN_KEY = "blackduck_token";

    @Deprecated
    public static final String BLACKDUCK_INSTALL_DIRECTORY_KEY = "blackduck_install_directory";

    @Deprecated
    public static final String BLACKDUCK_SCAN_FULL_KEY = "blackduck_scan_full";

    @Deprecated
    public static final String BLACKDUCK_SCAN_FAILURE_SEVERITIES_KEY = "blackduck_scan_failure_severities";

    @Deprecated
    public static final String BLACKDUCK_PRCOMMENT_ENABLED_KEY = "blackduck_prComment_enabled";

    @Deprecated
    public static final String BLACKDUCK_DOWNLOAD_URL_KEY = "blackduck_download_url";

    @Deprecated
    public static final String BLACKDUCK_REPORTS_SARIF_CREATE_KEY = "blackduck_reports_sarif_create";

    @Deprecated
    public static final String BLACKDUCK_REPORTS_SARIF_FILE_PATH_KEY = "blackduck_reports_sarif_file_path";

    @Deprecated
    public static final String BLACKDUCK_REPORTS_SARIF_GROUPSCAISSUES_KEY = "blackduck_reports_sarif_groupSCAIssues";

    @Deprecated
    public static final String BLACKDUCK_REPORTS_SARIF_SEVERITIES_KEY = "blackduck_reports_sarif_severities";

    @Deprecated
    public static final String BLACKDUCK_WAITFORSCAN_KEY = "blackduck_waitForScan";

    @Deprecated
    public static final String BLACKDUCK_SEARCH_DEPTH_KEY = "blackduck_search_depth";

    @Deprecated
    public static final String BLACKDUCK_CONFIG_PATH_KEY = "blackduck_config_path";

    @Deprecated
    public static final String BLACKDUCK_ARGS_KEY = "blackduck_args";

    @Deprecated
    public static final String BLACKDUCK_EXECUTION_PATH_KEY = "blackduck_execution_path";

    // Black Duck SCA Parameters
    public static final String BLACKDUCKSCA_URL_KEY = "blackducksca_url";
    public static final String BLACKDUCKSCA_TOKEN_KEY = "blackducksca_token";
    public static final String BLACKDUCKSCA_SCAN_FULL_KEY = "blackducksca_scan_full";
    public static final String BLACKDUCKSCA_SCAN_FAILURE_SEVERITIES_KEY = "blackducksca_scan_failure_severities";
    public static final String BLACKDUCKSCA_PRCOMMENT_ENABLED_KEY = "blackducksca_prComment_enabled";
    public static final String BLACKDUCKSCA_FIXPR_ENABLED_KEY = "blackducksca_fixpr_enabled";
    public static final String BLACKDUCKSCA_FIXPR_FILTER_SEVERITIES_KEY = "blackducksca_fixpr_filter_severities";
    public static final String BLACKDUCKSCA_FIXPR_USEUPGRADEGUIDANCE_KEY = "blackducksca_fixpr_useUpgradeGuidance";
    public static final String BLACKDUCKSCA_FIXPR_MAXCOUNT_KEY = "blackducksca_fixpr_maxcount";
    public static final String BLACKDUCKSCA_REPORTS_SARIF_CREATE_KEY = "blackducksca_reports_sarif_create";
    public static final String BLACKDUCKSCA_REPORTS_SARIF_FILE_PATH_KEY = "blackducksca_reports_sarif_file_path";
    public static final String BLACKDUCKSCA_REPORTS_SARIF_GROUPSCAISSUES_KEY =
            "blackducksca_reports_sarif_groupSCAIssues";
    public static final String BLACKDUCKSCA_REPORTS_SARIF_SEVERITIES_KEY = "blackducksca_reports_sarif_severities";
    public static final String DETECT_INSTALL_DIRECTORY_KEY = "detect_install_directory";
    public static final String DETECT_DOWNLOAD_URL_KEY = "detect_download_url";
    public static final String DETECT_SEARCH_DEPTH_KEY = "detect_search_depth";
    public static final String DETECT_CONFIG_PATH_KEY = "detect_config_path";
    public static final String DETECT_ARGS_KEY = "detect_args";
    public static final String DETECT_EXECUTION_PATH_KEY = "detect_execution_path";
    public static final String BLACKDUCKSCA_WAITFORSCAN_KEY = "blackducksca_waitForScan";

    // Coverity Parameters
    public static final String COVERITY_URL_KEY = "coverity_url";
    public static final String COVERITY_USER_KEY = "coverity_user";
    public static final String COVERITY_PASSPHRASE_KEY = "coverity_passphrase";
    public static final String COVERITY_PROJECT_NAME_KEY = "coverity_project_name";
    public static final String COVERITY_STREAM_NAME_KEY = "coverity_stream_name";
    public static final String COVERITY_POLICY_VIEW_KEY = "coverity_policy_view";
    public static final String COVERITY_INSTALL_DIRECTORY_KEY = "coverity_install_directory";
    public static final String COVERITY_BUILD_COMMAND_KEY = "coverity_build_command";
    public static final String COVERITY_CLEAN_COMMAND_KEY = "coverity_clean_command";
    public static final String COVERITY_CONFIG_PATH_KEY = "coverity_config_path";
    public static final String COVERITY_ARGS_KEY = "coverity_args";
    public static final String COVERITY_PRCOMMENT_ENABLED_KEY = "coverity_prComment_enabled";
    public static final String COVERITY_VERSION_KEY = "coverity_version";
    public static final String COVERITY_LOCAL_KEY = "coverity_local";
    public static final String COVERITY_EXECUTION_PATH_KEY = "coverity_execution_path";
    public static final String COVERITY_WAITFORSCAN_KEY = "coverity_waitForScan";

    // Polaris Parameters
    public static final String POLARIS_SERVER_URL_KEY = "polaris_server_url";
    public static final String POLARIS_ACCESS_TOKEN_KEY = "polaris_access_token";
    public static final String POLARIS_APPLICATION_NAME_KEY = "polaris_application_name";
    public static final String POLARIS_PROJECT_NAME_KEY = "polaris_project_name";
    public static final String POLARIS_ASSESSMENT_TYPES_KEY = "polaris_assessment_types";
    public static final String POLARIS_BRANCH_NAME_KEY = "polaris_branch_name";
    public static final String POLARIS_PRCOMMENT_ENABLED_KEY = "polaris_prComment_enabled";
    public static final String POLARIS_PRCOMMENT_SEVERITIES_KEY = "polaris_prComment_severities";
    public static final String POLARIS_BRANCH_PARENT_NAME_KEY = "polaris_branch_parent_name";
    public static final String POLARIS_REPORTS_SARIF_CREATE_KEY = "polaris_reports_sarif_create";
    public static final String POLARIS_REPORTS_SARIF_FILE_PATH_KEY = "polaris_reports_sarif_file_path";
    public static final String POLARIS_REPORTS_SARIF_GROUPSCAISSUES_KEY = "polaris_reports_sarif_groupSCAIssues";
    public static final String POLARIS_REPORTS_SARIF_SEVERITIES_KEY = "polaris_reports_sarif_severities";
    public static final String POLARIS_REPORTS_SARIF_ISSUE_TYPES_KEY = "polaris_reports_sarif_issue_types";
    public static final String POLARIS_ASSESSMENT_MODE_KEY = "polaris_assessment_mode";
    public static final String POLARIS_TEST_SCA_TYPE_KEY = "polaris_test_sca_type";
    public static final String POLARIS_WAITFORSCAN_KEY = "polaris_waitForScan";

    // SRM Parameters
    public static final String SRM_URL_KEY = "srm_url";
    public static final String SRM_APIKEY_KEY = "srm_apikey";
    public static final String SRM_ASSESSMENT_TYPES_KEY = "srm_assessment_types";
    public static final String SRM_PROJECT_NAME_KEY = "srm_project_name";
    public static final String SRM_PROJECT_ID_KEY = "srm_project_id";
    public static final String SRM_BRANCH_NAME_KEY = "srm_branch_name";
    public static final String SRM_BRANCH_PARENT_KEY = "srm_branch_parent";
    public static final String SRM_WAITFORSCAN_KEY = "srm_waitForScan";

    // Source Upload Parameters
    public static final String PROJECT_DIRECTORY_KEY = "project_directory";
    public static final String PROJECT_SOURCE_ARCHIVE_KEY = "project_source_archive";
    public static final String PROJECT_SOURCE_EXCLUDES_KEY = "project_source_excludes";
    public static final String PROJECT_SOURCE_PRESERVE_SYM_LINKS_KEY = "project_source_preserveSymLinks";

    // Additional Parameters
    public static final String INCLUDE_DIAGNOSTICS_KEY = "include_diagnostics";
    public static final String NETWORK_AIRGAP_KEY = "network_airgap";
    public static final String RETURN_STATUS_KEY = "return_status";
    public static final String BITBUCKET_USERNAME_KEY = "bitbucket_username";
    public static final String BITBUCKET_TOKEN_KEY = "bitbucket_token";
    public static final String GITHUB_TOKEN_KEY = "github_token";
    public static final String GITLAB_TOKEN_KEY = "gitlab_token";
    public static final String MARK_BUILD_STATUS = "mark_build_status";

    // Error Log Related Constants
    public static final String INVALID_SECURITY_PRODUCT = "Invalid Security Product";
    public static final String REQUIRED_PARAMETERS_FOR_SPECIFIC_JOB_TYPE_IS_MISSING =
            "%s - required parameters for %s job type is missing";
    public static final String REQUIRED_PARAMETERS_FOR_SPECIFIC_SCAN_TYPE_IS_MISSING =
            "%s - required parameters for %s is missing";
    public static final String REQUIRED_SRM_PROJECT_NAME_OR_ID = "One of %s or %s must be present.";
    public static final String INVALID_BRIDGE_CLI_URL = "Provided Bridge CLI URL is not valid: %s";
    public static final String BRIDGE_CLI_VERSION_NOT_FOUND =
            "Provided Bridge CLI version not found in artifactory: %s";
    public static final String PRCOMMENT_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND =
            "PrComment is set true but no %s token found!";
    public static final String FIXPR_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND = "FixPr is set true but no %s token found!";
    public static final String UNZIPPING_BRIDGE_CLI_ZIP_FILE =
            "An exception occurred while unzipping Bridge CLI Bundle zip file: %s";
    public static final String BRIDGE_DOWNLOAD_FAILED_AFTER_X_ATTEMPTS = "Bridge CLI download failed after %s attempts";
    public static final String ARCHIVING_REPORTS_IN_JENKINS_ARTIFACT =
            "An exception occurred while archiving %s in jenkins artifact: %s";
    public static final String ARCHIVING_REPORTS_FAILED_AS_REPORT_PATH_NOT_FOUND =
            "Archiving %s failed as %s path not found at: %s";
    public static final String VALIDATING_THE_INSTALLATION_PATH_EXCEPTION =
            "An exception occurred while validating the installation path: %s";
    public static final String BRIDGE_INSTALLATION_PARENT_PATH_IS_NOT_A_DIRECTORY =
            "The bridge installation parent path: %s is not a directory";
    public static final String BRIDGE_INSTALLATION_PARENT_PATH_DOES_NOT_EXIST =
            "The bridge installation parent path: %s doesn't exist";
    public static final String BRIDGE_INSTALLATION_PARENT_PATH_IS_NOT_WRITABLE =
            "The bridge installation parent path: %s is not writable";
    public static final String BRIDGE_DOWNLOAD_PARAMETERS_ARE_NOT_VALID = "Bridge download parameters are not valid";
    public static final String FAILED_TO_CREATE_JSON_FILE_IN_WORKSPACE_PARENT_PATH =
            "Failed to create json file in workspace parent path";
    public static final String WRITING_INTO_JSON_FILE_EXCEPTION =
            "An exception occurred while writing into json file: %s";
    public static final String CREATING_INPUT_JSON_FILE_EXCEPTION =
            "An exception occurred while creating input.json file: %s";
    public static final String HTTP_URL_CONNECTION_EXCEPTION =
            "An exception occurred while getting HttpURLConnection: %s";
    public static final String DELETING_FILE_EXCEPTION = "An exception occurred while deleting file: %s";
    public static final String FETCHING_OS_ARCHITECTURE_INFORMATION_FOR_THE_AGENT_NODE_EXCEPTION =
            "An exception occurred while fetching the OS architecture information for the agent node: %s";
    public static final String FETCHING_OS_INFORMATION_FOR_THE_AGENT_NODE_EXCEPTION =
            "An exception occurred while fetching the OS information for the agent node: %s";
    public static final String NECESSARY_BRANCH_SOURCE_PLUGIN_IS_NOT_INSTALLED =
            "Necessary 'Branch Source Plugin' is not installed in Jenkins instance. Please install necessary 'Branch Source Plugin' in your Jenkins instance";
    public static final String FAILED_TO_CREATE_DEFAULT_INSTALLATION_DIRECTORY =
            "Failed to create default installation directory: %s";
    public static final String FAILED_TO_FETCH_PLUGINS_DEFAULT_INSTALLATION_PATH =
            "Failed to fetch plugin's default installation path: %s";
    public static final String EXCEPTION_WHILE_GETTING_THE_BITBUCKET_REPOSITORY_FROM_BITBUCKET_API =
            "An exception occurred while getting the BitbucketRepository from BitbucketApi: %s";
    public static final String EXCEPTION_WHILE_GETTING_DIRECTORY_URL_FROM_DOWNLOAD_URL =
            "An exception occurred while getting directoryUrl from downloadUrl: %s";
    public static final String EXCEPTION_WHILE_CHECKING_VERSIONS_TXT_IS_AVAILABLE_OR_NOT_IN_THE_URL =
            "An exception occurred while checking if 'versions.txt' is available or not in the URL: %s";
    public static final String EXCEPTION_WHILE_DOWNLOADING_VERSIONS_TXT =
            "An exception occurred while downloading 'versions.txt': %s";
    public static final String EXCEPTION_WHILE_EXTRACTING_BRIDGE_VERSION_FROM_VERSIONS_TXT =
            "An exception occurred while extracting bridge-version from the 'versions.txt': %s";
    public static final String BRIDGE_CLI_DOWNLOAD_FAILED_WITH_STATUS_CODE =
            "Bridge CLI download failed with status code: %s and plugin won't retry to download";
    public static final String BRIDGE_CLI_EXECUTABLE_FILE_NOT_FOUND =
            "Bridge CLI executable file could not be found at %s";
    public static final String EXCEPTION_WHILE_INVOKING_BRIDGE_CLI =
            "An exception occurred while invoking bridge-cli from the plugin: %s";
    public static final String INTERRUPTED_WHILE_WAITING_TO_RETRY_BRIDGE_CLI_DOWNLOAD =
            "Interrupted while waiting to retry Bridge CLI download";
    public static final String EXCEPTION_WHILE_CHECKING_THE_HTTP_STATUS_CODE =
            "An exception occurred while checking the http status code: %s";
    public static final String EXCEPTION_WHILE_CHECKING_BRIDGE_URL_EXISTS_OR_NOT =
            "An exception occurred while checking bridge url exists or not: %s";
    public static final String EXCEPTION_WHILE_CHECKING_IF_THE_BRIDGE_IS_INSTALLED =
            "An exception occurred while checking if the bridge is installed: %s";

    // Warn Log Related Constants
    public static final String BRIDGE_CLI_WILL_BE_DOWNLOADED_FROM_THE_PROVIDED_CUSTOM_URL =
            "Bridge-CLI will be downloaded from the provided custom URL. Make sure the network is reachable";
    public static final String INVALID_BRIDGE_CLI_DOWNLOAD_URL = "Invalid Bridge CLI download URL: %s";
    public static final String EXCEPTION_OCCURRED_IN_BETWEEN_CONSECUTIVE_RETRY_ATTEMPTS =
            "An exception occurred in between consecutive retry attempts: %s";
    public static final String BRIDGE_CLI_DOWNLOAD_FAILED_AND_ATTEMPT_TO_DOWNLOAD_AGAIN =
            "Bridge CLI download failed and attempt#%s to download again.";
    public static final String EXCEPTION_WHILE_DELETING_BRIDGE_CLI_ZIP_FILE =
            "An exception occurred while deleting Bridge CLI Bundle zip file: %s";
    public static final String EMPTY_BRIDGE_CLI_URL = "Provided Bridge CLI URL cannot be empty";
    public static final String UNSUPPORTED_VALUE_FOR_MARK_BUILD_STATUS_AND_SUPPORTED_VALUES_FOR_BUILD_STATUS =
            "Unsupported value for %s: %s. Supported values are: %s";
    public static final String
            DEPRECATED_PARAMETERS_WILL_BE_REMOVED_IN_FUTURE_AND_CHECK_DOCUMENTATION_FOR_NEW_PARAMETERS =
                    "%s is/are deprecated and will be removed in future. Check documentation for new parameters: %s";
    public static final String
            DEPRECATED_PRODUCT_WILL_BE_REMOVED_IN_FUTURE_AND_RECOMMENDING_TO_USE_NEW_PRODUCT_AND_ITS_PARAMETERS =
                    "%s product is deprecated and will be removed in future. Please use %s and its corresponding parameters instead.";

    // Info Log Related Issue Count
    public static final String SCAN_INFO_FILE_NOT_FOUND = "File for issue count does not exist";
    public static final String EXCEPTION_WHILE_PROCESS_SCAN_INFO_FILE =
            "An exception occurred while processing JSON file for Issue count: %s";
    public static final String SCAN_INFO_ISSUE_COUNT_NOT_FOUND = "Issue count not found in output file";

    // Bridge Download Parameters
    @Deprecated
    public static final String SYNOPSYS_BRIDGE_DOWNLOAD_URL = "synopsys_bridge_download_url";

    @Deprecated
    public static final String SYNOPSYS_BRIDGE_DOWNLOAD_VERSION = "synopsys_bridge_download_version";

    @Deprecated
    public static final String SYNOPSYS_BRIDGE_INSTALL_DIRECTORY = "synopsys_bridge_install_directory";

    public static final String BRIDGECLI_DOWNLOAD_URL = "bridgecli_download_url";
    public static final String BRIDGECLI_DOWNLOAD_VERSION = "bridgecli_download_version";
    public static final String BRIDGECLI_INSTALL_DIRECTORY = "bridgecli_install_directory";

    public static final String BLACKDUCKSCA_INPUT_JSON_PREFIX = "blackducksca_input";
    public static final String COVERITY_INPUT_JSON_PREFIX = "coverity_input";
    public static final String POLARIS_INPUT_JSON_PREFIX = "polaris_input";
    public static final String SRM_INPUT_JSON_PREFIX = "srm_input";

    public static final String HTTPS_PROXY = "HTTPS_PROXY";
    public static final String HTTP_PROXY = "HTTP_PROXY";
    public static final String NO_PROXY = "NO_PROXY";

    // Test Connection APIs
    public static final String BLACKDUCKSCA_AUTH_API = "api/tokens/authenticate";
    public static final String POLARIS_PORTFOLIO_API = "api/portfolio/portfolios";
    public static final String COVERITY_LOCALES_API = "api/v2/locales";
    public static final String SRM_SYSTEM_INFO_API = "srm/api/system-info";
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    public static final String BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME = "cloudbees-bitbucket-branch-source";
    public static final String GITHUB_BRANCH_SOURCE_PLUGIN_NAME = "github-branch-source";
    public static final String GITLAB_BRANCH_SOURCE_PLUGIN_NAME = "gitlab-branch-source";

    public static final String MULTIBRANCH_JOB_TYPE_NAME = "WorkflowMultiBranchProject";
    public static final String FREESTYLE_JOB_TYPE_NAME = "FreeStyleProject";

    public static final String DEFAULT_DROPDOWN_OPTION_NAME = "Select";

    public static final String BLACKDUCK_PRCOMMENT_INFO_FOR_NON_PR_SCANS =
            "Black Duck SCA PR Comment is ignored for non pull request scan";
    public static final String COVERITY_PRCOMMENT_INFO_FOR_NON_PR_SCANS =
            "Coverity PR Comment is ignored for non pull request scan";
    public static final String POLARIS_PRCOMMENT_INFO_FOR_NON_PR_SCANS =
            "Polaris PR Comment is ignored for non pull request scan";

    public static final String BLACKDUCK_FIXPR_INFO_FOR_NON_PR_SCANS =
            "Black Duck SCA Fix PR ignored for pull request scan";

    public static final String BLACKDUCK_SECURITY_SCAN_PLUGIN_DOCS_URL =
            "https://documentation.blackduck.com/bundle/bridge/page/documentation/c_using-jenkins-plugin.html";

    public static final List<String> ARBITRARY_PARAM_KEYS = List.of(
            DETECT_SEARCH_DEPTH_KEY,
            DETECT_CONFIG_PATH_KEY,
            DETECT_ARGS_KEY,
            COVERITY_BUILD_COMMAND_KEY,
            COVERITY_CLEAN_COMMAND_KEY,
            COVERITY_CONFIG_PATH_KEY,
            COVERITY_ARGS_KEY);
}
