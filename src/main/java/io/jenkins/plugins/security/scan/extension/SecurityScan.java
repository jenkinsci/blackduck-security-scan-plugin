package io.jenkins.plugins.security.scan.extension;

public interface SecurityScan {
    public String getProduct();

    public String getBlackducksca_url();

    public String getBlackducksca_token();

    public String getDetect_install_directory();

    public Boolean isBlackducksca_scan_full();

    public Boolean isBlackduckscaIntelligentScan();

    public String getBlackducksca_scan_failure_severities();

    public String getDetect_download_url();

    public Integer getDetect_search_depth();

    public String getDetect_config_path();

    public String getDetect_args();

    public String getDetect_execution_path();

    public Boolean isBlackducksca_reports_sarif_create();

    public String getBlackducksca_reports_sarif_file_path();

    public Boolean isBlackducksca_reports_sarif_groupSCAIssues();

    public String getBlackducksca_reports_sarif_severities();

    public Boolean isBlackducksca_reports_sarif_groupSCAIssues_temporary();

    public Boolean isBlackducksca_waitForScan();

    public Boolean isBlackducksca_waitForScan_actualValue();

    @Deprecated
    public String getBlackduck_url();

    @Deprecated
    public String getBlackduck_token();

    @Deprecated
    public String getBlackduck_install_directory();

    @Deprecated
    public Boolean isBlackduck_scan_full();

    @Deprecated
    public Boolean isBlackduckIntelligentScan();

    @Deprecated
    public String getBlackduck_scan_failure_severities();

    @Deprecated
    public String getBlackduck_download_url();

    @Deprecated
    public Integer getBlackduck_search_depth();

    @Deprecated
    public String getBlackduck_config_path();

    @Deprecated
    public String getBlackduck_args();

    @Deprecated
    public String getBlackduck_execution_path();

    @Deprecated
    public Boolean isBlackduck_reports_sarif_create();

    @Deprecated
    public String getBlackduck_reports_sarif_file_path();

    @Deprecated
    public Boolean isBlackduck_reports_sarif_groupSCAIssues();

    @Deprecated
    public String getBlackduck_reports_sarif_severities();

    @Deprecated
    public Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary();

    @Deprecated
    public Boolean isBlackduck_waitForScan();

    @Deprecated
    public Boolean isBlackduck_waitForScan_actualValue();

    public String getCoverity_url();

    public String getCoverity_user();

    public String getCoverity_passphrase();

    public String getCoverity_project_name();

    public String getCoverity_stream_name();

    public String getCoverity_policy_view();

    public String getCoverity_install_directory();

    public String getCoverity_build_command();

    public String getCoverity_clean_command();

    public String getCoverity_config_path();

    public String getCoverity_args();

    public String getCoverity_version();

    public Boolean isCoverity_local();

    public Boolean isCoverity_waitForScan();

    public Boolean isCoverity_waitForScan_actualValue();

    public String getCoverity_execution_path();

    public String getPolaris_server_url();

    public String getPolaris_access_token();

    public String getPolaris_application_name();

    public String getPolaris_project_name();

    public String getPolaris_assessment_types();

    public String getPolaris_branch_name();

    public String getPolaris_branch_parent_name();

    public String getPolaris_test_sca_type();

    public String getBitbucket_username();

    public Boolean isPolaris_reports_sarif_create();

    public String getPolaris_reports_sarif_file_path();

    public Boolean isPolaris_reports_sarif_groupSCAIssues();

    public String getPolaris_reports_sarif_severities();

    public String getPolaris_reports_sarif_issue_types();

    public Boolean isPolaris_reports_sarif_groupSCAIssues_temporary();

    public Boolean isPolaris_waitForScan();

    public Boolean isPolaris_waitForScan_actualValue();

    public String getPolaris_assessment_mode();

    public String getProject_source_archive();

    public Boolean isProject_source_preserveSymLinks();

    public Boolean isProject_source_preserveSymLinks_actualValue();

    public String getProject_source_excludes();

    public String getProject_directory();

    public String getSrm_url();

    public String getSrm_apikey();

    public String getSrm_project_name();

    public String getSrm_project_id();

    public String getSrm_assessment_types();

    public String getSrm_branch_name();

    public String getSrm_branch_parent();

    public Boolean isSrm_waitForScan();

    public Boolean isSrm_waitForScan_actualValue();

    public String getBitbucket_token();

    public String getGithub_token();

    public String getGitlab_token();

    @Deprecated
    public String getSynopsys_bridge_download_url();

    @Deprecated
    public String getSynopsys_bridge_download_version();

    @Deprecated
    public String getSynopsys_bridge_install_directory();

    public String getBridgecli_download_url();

    public String getBridgecli_download_version();

    public String getBridgecli_install_directory();

    public Boolean isInclude_diagnostics();

    public String getMark_build_status();
}
