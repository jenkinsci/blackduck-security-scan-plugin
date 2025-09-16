package io.jenkins.plugins.security.scan.extension;

public interface SecurityScan {
    String getProduct();

    String getBlackducksca_url();

    String getBlackducksca_token();

    String getDetect_install_directory();

    Boolean isBlackducksca_scan_full();

    Boolean isBlackduckscaIntelligentScan();

    String getBlackducksca_scan_failure_severities();

    String getDetect_download_url();

    Integer getDetect_search_depth();

    String getDetect_config_path();

    String getDetect_args();

    String getDetect_execution_path();

    Boolean isBlackducksca_reports_sarif_create();

    String getBlackducksca_reports_sarif_file_path();

    Boolean isBlackducksca_reports_sarif_groupSCAIssues();

    String getBlackducksca_reports_sarif_severities();

    Boolean isBlackducksca_reports_sarif_groupSCAIssues_temporary();

    Boolean isBlackducksca_waitForScan();

    Boolean isBlackducksca_waitForScan_actualValue();

    @Deprecated
    String getBlackduck_url();

    @Deprecated
    String getBlackduck_token();

    @Deprecated
    String getBlackduck_install_directory();

    @Deprecated
    Boolean isBlackduck_scan_full();

    @Deprecated
    Boolean isBlackduckIntelligentScan();

    @Deprecated
    String getBlackduck_scan_failure_severities();

    @Deprecated
    String getBlackduck_download_url();

    @Deprecated
    Integer getBlackduck_search_depth();

    @Deprecated
    String getBlackduck_config_path();

    @Deprecated
    String getBlackduck_args();

    @Deprecated
    String getBlackduck_execution_path();

    @Deprecated
    Boolean isBlackduck_reports_sarif_create();

    @Deprecated
    String getBlackduck_reports_sarif_file_path();

    @Deprecated
    Boolean isBlackduck_reports_sarif_groupSCAIssues();

    @Deprecated
    String getBlackduck_reports_sarif_severities();

    @Deprecated
    Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary();

    @Deprecated
    Boolean isBlackduck_waitForScan();

    @Deprecated
    Boolean isBlackduck_waitForScan_actualValue();

    String getCoverity_url();

    String getCoverity_user();

    String getCoverity_passphrase();

    String getCoverity_project_name();

    String getCoverity_stream_name();

    String getCoverity_policy_view();

    String getCoverity_install_directory();

    String getCoverity_build_command();

    String getCoverity_clean_command();

    String getCoverity_config_path();

    String getCoverity_args();

    String getCoverity_version();

    Boolean isCoverity_local();

    Boolean isCoverity_waitForScan();

    Boolean isCoverity_waitForScan_actualValue();

    String getCoverity_execution_path();

    String getPolaris_server_url();

    String getPolaris_access_token();

    String getPolaris_application_name();

    String getPolaris_project_name();

    String getPolaris_assessment_types();

    String getPolaris_branch_name();

    String getPolaris_branch_parent_name();

    String getPolaris_test_sca_type();

    String getPolaris_test_sast_type();

    String getPolaris_test_sca_location();

    String getPolaris_test_sast_location();

    String getBitbucket_username();

    Boolean isPolaris_reports_sarif_create();

    String getPolaris_reports_sarif_file_path();

    Boolean isPolaris_reports_sarif_groupSCAIssues();

    String getPolaris_reports_sarif_severities();

    String getPolaris_reports_sarif_issue_types();

    Boolean isPolaris_reports_sarif_groupSCAIssues_temporary();

    Boolean isPolaris_waitForScan();

    Boolean isPolaris_waitForScan_actualValue();

    @Deprecated
    String getPolaris_assessment_mode();

    String getProject_source_archive();

    Boolean isProject_source_preserveSymLinks();

    Boolean isProject_source_preserveSymLinks_actualValue();

    String getProject_source_excludes();

    String getProject_directory();

    String getSrm_url();

    String getSrm_apikey();

    String getSrm_project_name();

    String getSrm_project_id();

    String getSrm_assessment_types();

    String getSrm_branch_name();

    String getSrm_branch_parent();

    Boolean isSrm_waitForScan();

    Boolean isSrm_waitForScan_actualValue();

    String getBitbucket_token();

    String getGithub_token();

    String getGitlab_token();

    @Deprecated
    String getSynopsys_bridge_download_url();

    @Deprecated
    String getSynopsys_bridge_download_version();

    @Deprecated
    String getSynopsys_bridge_install_directory();

    String getBridgecli_download_url();

    String getBridgecli_download_version();

    String getBridgecli_install_directory();

    Boolean isInclude_diagnostics();

    String getMark_build_status();
}
