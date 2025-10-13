package io.jenkins.plugins.security.scan.extension.freestyle;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.*;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.security.scan.ScanInitializer;
import io.jenkins.plugins.security.scan.SecurityScanner;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.exception.ScannerException;
import io.jenkins.plugins.security.scan.extension.SecurityScan;
import io.jenkins.plugins.security.scan.global.*;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.ParameterMappingService;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import jenkins.tasks.SimpleBuildStep;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class SecurityScanFreestyle extends Builder implements SecurityScan, FreestyleScan, SimpleBuildStep {
    private final Boolean NULL = null;

    private String product;
    private String blackducksca_url;
    private transient String blackducksca_token;
    private String blackducksca_scan_failure_severities;
    private Boolean blackducksca_reports_sarif_create;
    private String blackducksca_reports_sarif_file_path;
    private Boolean blackducksca_reports_sarif_groupSCAIssues;
    private String blackducksca_reports_sarif_severities;
    private Boolean blackducksca_reports_sarif_groupSCAIssues_temporary;
    private Boolean blackducksca_waitForScan;
    private Boolean blackducksca_waitForScan_actualValue;
    private String detect_install_directory;
    private Boolean blackducksca_scan_full;
    private Boolean blackduckscaIntelligentScan;
    private String detect_download_url;
    private Integer detect_search_depth;
    private String detect_config_path;
    private String detect_args;
    private String detect_execution_path;

    private String coverity_url;
    private String coverity_user;
    private transient String coverity_passphrase;
    private String coverity_project_name;
    private String coverity_stream_name;
    private String coverity_policy_view;
    private String coverity_install_directory;
    private String coverity_version;
    private Boolean coverity_local;
    private String coverity_build_command;
    private String coverity_clean_command;
    private String coverity_config_path;
    private String coverity_args;
    private String coverity_execution_path;
    private Boolean coverity_waitForScan;
    private Boolean coverity_waitForScan_actualValue;

    private String polaris_server_url;
    private transient String polaris_access_token;
    private String polaris_application_name;
    private String polaris_project_name;
    private String polaris_assessment_types;
    private String polaris_branch_name;
    private String polaris_branch_parent_name;
    private Boolean polaris_reports_sarif_create;
    private String polaris_reports_sarif_file_path;
    private String polaris_reports_sarif_issue_types;
    private Boolean polaris_reports_sarif_groupSCAIssues;
    private String polaris_reports_sarif_severities;
    private Boolean polaris_reports_sarif_groupSCAIssues_temporary;
    private String project_source_archive;
    private String polaris_assessment_mode;
    private String project_source_excludes;
    private Boolean project_source_preserveSymLinks;
    private Boolean project_source_preserveSymLinks_actualValue;
    private String project_directory;
    private String polaris_test_sca_type;
    private String polaris_test_sast_type;
    private String coverity_project_directory;
    private String blackducksca_project_directory;
    private String polaris_project_directory;
    private Integer polaris_sca_search_depth;
    private String polaris_sca_config_path;
    private String polaris_sca_args;
    private String polaris_sast_build_command;
    private String polaris_sast_clean_command;
    private String polaris_sast_config_path;
    private String polaris_sast_args;
    private Boolean polaris_waitForScan;
    private Boolean polaris_waitForScan_actualValue;

    private String srm_url;
    private transient String srm_apikey;
    private String srm_assessment_types;
    private String srm_project_name;
    private String srm_project_id;
    private String srm_branch_name;
    private String srm_branch_parent;
    private String srm_project_directory;
    private Integer srm_sca_search_depth;
    private String srm_sca_config_path;
    private String srm_sca_args;
    private String srm_sast_build_command;
    private String srm_sast_clean_command;
    private String srm_sast_config_path;
    private String srm_sast_args;
    private Boolean srm_waitForScan;
    private Boolean srm_waitForScan_actualValue;

    private String bitbucket_username;
    private transient String bitbucket_token;
    private transient String github_token;
    private transient String gitlab_token;

    private String bridgecli_download_url;
    private String bridgecli_download_version;
    private String bridgecli_install_directory;
    private Boolean include_diagnostics;
    private Boolean coverity_include_diagnostics;
    private Boolean blackducksca_include_diagnostics;
    private Boolean polaris_include_diagnostics;
    private Boolean srm_include_diagnostics;

    private String mark_build_status;
    private String blackducksca_mark_build_status;
    private String coverity_mark_build_status;
    private String polaris_mark_build_status;
    private String srm_mark_build_status;

    @DataBoundConstructor
    public SecurityScanFreestyle() {
        // this block is kept empty intentionally
    }

    public String getProduct() {
        return product;
    }

    public String getBlackducksca_url() {
        return blackducksca_url;
    }

    public String getBlackducksca_token() {
        return blackducksca_token;
    }

    public String getDetect_install_directory() {
        return detect_install_directory;
    }

    public Boolean isBlackducksca_scan_full() {
        return blackducksca_scan_full;
    }

    public Boolean isBlackduckscaIntelligentScan() {
        return blackduckscaIntelligentScan;
    }

    public String getBlackducksca_scan_failure_severities() {
        return blackducksca_scan_failure_severities;
    }

    public String getDetect_download_url() {
        return detect_download_url;
    }

    public Boolean isBlackducksca_reports_sarif_create() {
        return blackducksca_reports_sarif_create;
    }

    public String getBlackducksca_reports_sarif_file_path() {
        return blackducksca_reports_sarif_file_path;
    }

    public Boolean isBlackducksca_reports_sarif_groupSCAIssues() {
        return blackducksca_reports_sarif_groupSCAIssues;
    }

    public String getBlackducksca_reports_sarif_severities() {
        return blackducksca_reports_sarif_severities;
    }

    public Boolean isBlackducksca_reports_sarif_groupSCAIssues_temporary() {
        return blackducksca_reports_sarif_groupSCAIssues_temporary;
    }

    public Boolean isBlackducksca_waitForScan() {
        return blackducksca_waitForScan;
    }

    public Boolean isBlackducksca_waitForScan_actualValue() {
        return blackducksca_waitForScan_actualValue;
    }

    public Integer getDetect_search_depth() {
        return detect_search_depth;
    }

    public String getDetect_config_path() {
        return detect_config_path;
    }

    public String getDetect_args() {
        return detect_args;
    }

    public String getDetect_execution_path() {
        return detect_execution_path;
    }

    public String getBlackduck_url() {
        return null;
    }

    public String getBlackduck_token() {
        return null;
    }

    public String getBlackduck_install_directory() {
        return null;
    }

    public Boolean isBlackduck_scan_full() {
        return NULL;
    }

    public Boolean isBlackduckIntelligentScan() {
        return NULL;
    }

    public String getBlackduck_scan_failure_severities() {
        return null;
    }

    public String getBlackduck_download_url() {
        return null;
    }

    public Integer getBlackduck_search_depth() {
        return null;
    }

    public String getBlackduck_config_path() {
        return null;
    }

    public String getBlackduck_args() {
        return null;
    }

    public String getBlackduck_execution_path() {
        return null;
    }

    public Boolean isBlackduck_reports_sarif_create() {
        return NULL;
    }

    public String getBlackduck_reports_sarif_file_path() {
        return null;
    }

    public String getBlackduck_reports_sarif_severities() {
        return null;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues() {
        return NULL;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary() {
        return NULL;
    }

    public Boolean isBlackduck_waitForScan() {
        return NULL;
    }

    public Boolean isBlackduck_waitForScan_actualValue() {
        return NULL;
    }

    public String getCoverity_url() {
        return coverity_url;
    }

    public String getCoverity_user() {
        return coverity_user;
    }

    public String getCoverity_passphrase() {
        return coverity_passphrase;
    }

    public String getCoverity_project_name() {
        return coverity_project_name;
    }

    public String getCoverity_stream_name() {
        return coverity_stream_name;
    }

    public String getCoverity_policy_view() {
        return coverity_policy_view;
    }

    public String getCoverity_install_directory() {
        return coverity_install_directory;
    }

    public String getCoverity_version() {
        return coverity_version;
    }

    public Boolean isCoverity_local() {
        return coverity_local;
    }

    public String getCoverity_build_command() {
        return coverity_build_command;
    }

    public String getCoverity_clean_command() {
        return coverity_clean_command;
    }

    public String getCoverity_config_path() {
        return coverity_config_path;
    }

    public String getCoverity_args() {
        return coverity_args;
    }

    public String getCoverity_execution_path() {
        return coverity_execution_path;
    }

    public Boolean isCoverity_waitForScan() {
        return coverity_waitForScan;
    }

    public Boolean isCoverity_waitForScan_actualValue() {
        return coverity_waitForScan_actualValue;
    }

    public String getPolaris_server_url() {
        return polaris_server_url;
    }

    public String getPolaris_access_token() {
        return polaris_access_token;
    }

    public String getPolaris_application_name() {
        return polaris_application_name;
    }

    public String getPolaris_project_name() {
        return polaris_project_name;
    }

    public String getPolaris_assessment_types() {
        return polaris_assessment_types;
    }

    public String getPolaris_branch_name() {
        return polaris_branch_name;
    }

    public String getPolaris_branch_parent_name() {
        return polaris_branch_parent_name;
    }

    public Boolean isPolaris_reports_sarif_create() {
        return polaris_reports_sarif_create;
    }

    public String getPolaris_reports_sarif_file_path() {
        return polaris_reports_sarif_file_path;
    }

    public Boolean isPolaris_reports_sarif_groupSCAIssues() {
        return polaris_reports_sarif_groupSCAIssues;
    }

    public String getPolaris_reports_sarif_severities() {
        return polaris_reports_sarif_severities;
    }

    public String getPolaris_reports_sarif_issue_types() {
        return polaris_reports_sarif_issue_types;
    }

    public Boolean isPolaris_reports_sarif_groupSCAIssues_temporary() {
        return polaris_reports_sarif_groupSCAIssues_temporary;
    }

    public String getPolaris_assessment_mode() {
        return polaris_assessment_mode;
    }

    public String getPolaris_test_sca_type() {
        return polaris_test_sca_type;
    }

    public String getPolaris_test_sast_type() {
        return polaris_test_sast_type;
    }

    public Integer getPolaris_sca_search_depth() {
        return polaris_sca_search_depth;
    }

    public String getPolaris_sca_config_path() {
        return polaris_sca_config_path;
    }

    public String getPolaris_sca_args() {
        return polaris_sca_args;
    }

    public String getPolaris_sast_build_command() {
        return polaris_sast_build_command;
    }

    public String getPolaris_sast_clean_command() {
        return polaris_sast_clean_command;
    }

    public String getPolaris_sast_config_path() {
        return polaris_sast_config_path;
    }

    public String getPolaris_sast_args() {
        return polaris_sast_args;
    }

    public String getProject_source_archive() {
        return project_source_archive;
    }

    public Boolean isProject_source_preserveSymLinks() {
        return project_source_preserveSymLinks;
    }

    public Boolean isProject_source_preserveSymLinks_actualValue() {
        return project_source_preserveSymLinks_actualValue;
    }

    public String getProject_source_excludes() {
        return project_source_excludes;
    }

    public String getProject_directory() {
        return project_directory;
    }

    public Boolean isPolaris_waitForScan() {
        return polaris_waitForScan;
    }

    public Boolean isPolaris_waitForScan_actualValue() {
        return polaris_waitForScan_actualValue;
    }

    public String getBlackducksca_project_directory() {
        return blackducksca_project_directory;
    }

    public String getCoverity_project_directory() {
        return coverity_project_directory;
    }

    public String getPolaris_project_directory() {
        return polaris_project_directory;
    }

    public String getSrm_project_directory() {
        return srm_project_directory;
    }

    public String getBitbucket_username() {
        return bitbucket_username;
    }

    public String getBitbucket_token() {
        return bitbucket_token;
    }

    public String getGithub_token() {
        return github_token;
    }

    public String getGitlab_token() {
        return gitlab_token;
    }

    public String getBridgecli_download_url() {
        return bridgecli_download_url;
    }

    public String getBridgecli_download_version() {
        return bridgecli_download_version;
    }

    public String getBridgecli_install_directory() {
        return bridgecli_install_directory;
    }

    public String getSynopsys_bridge_download_url() {
        return null;
    }

    public String getSynopsys_bridge_download_version() {
        return null;
    }

    public String getSynopsys_bridge_install_directory() {
        return null;
    }

    public Boolean isInclude_diagnostics() {
        return include_diagnostics;
    }

    public Boolean isCoverity_include_diagnostics() {
        return coverity_include_diagnostics;
    }

    public Boolean isBlackducksca_include_diagnostics() {
        return blackducksca_include_diagnostics;
    }

    public Boolean isPolaris_include_diagnostics() {
        return polaris_include_diagnostics;
    }

    public Boolean isSrm_include_diagnostics() {
        return srm_include_diagnostics;
    }

    public String getMark_build_status() {
        return mark_build_status;
    }

    public String getBlackducksca_mark_build_status() {
        return blackducksca_mark_build_status;
    }

    public String getCoverity_mark_build_status() {
        return coverity_mark_build_status;
    }

    public String getPolaris_mark_build_status() {
        return polaris_mark_build_status;
    }

    public String getSrm_mark_build_status() {
        return srm_mark_build_status;
    }

    public String getSrm_url() {
        return srm_url;
    }

    public String getSrm_apikey() {
        return srm_apikey;
    }

    public String getSrm_project_name() {
        return srm_project_name;
    }

    public String getSrm_project_id() {
        return srm_project_id;
    }

    public String getSrm_assessment_types() {
        return srm_assessment_types;
    }

    public String getSrm_branch_name() {
        return srm_branch_name;
    }

    public String getSrm_branch_parent() {
        return srm_branch_parent;
    }

    public Integer getSrm_sca_search_depth() {
        return srm_sca_search_depth;
    }

    public String getSrm_sca_config_path() {
        return srm_sca_config_path;
    }

    public String getSrm_sca_args() {
        return srm_sca_args;
    }

    public String getSrm_sast_build_command() {
        return srm_sast_build_command;
    }

    public String getSrm_sast_clean_command() {
        return srm_sast_clean_command;
    }

    public String getSrm_sast_config_path() {
        return srm_sast_config_path;
    }

    public String getSrm_sast_args() {
        return srm_sast_args;
    }

    public Boolean isSrm_waitForScan() {
        return srm_waitForScan;
    }

    public Boolean isSrm_waitForScan_actualValue() {
        return srm_waitForScan_actualValue;
    }

    @DataBoundSetter
    public void setProduct(String product) {
        this.product = product;
    }

    @DataBoundSetter
    public void setBlackducksca_url(String blackducksca_url) {
        this.blackducksca_url = blackducksca_url;
    }

    @DataBoundSetter
    public void setBlackducksca_token(String blackducksca_token) {
        this.blackducksca_token = blackducksca_token;
    }

    @DataBoundSetter
    public void setDetect_install_directory(String detect_install_directory) {
        this.detect_install_directory = detect_install_directory;
    }

    @DataBoundSetter
    public void setBlackducksca_scan_full(String blackducksca_scan_full) {
        if (blackducksca_scan_full == null || blackducksca_scan_full.trim().isEmpty()) {
            this.blackducksca_scan_full = null;
            this.blackduckscaIntelligentScan = null;
        } else if ("true".equals(blackducksca_scan_full.trim())) {
            this.blackducksca_scan_full = Boolean.TRUE;
            this.blackduckscaIntelligentScan = Boolean.FALSE;
        } else if ("false".equals(blackducksca_scan_full.trim())) {
            this.blackducksca_scan_full = Boolean.FALSE;
            this.blackduckscaIntelligentScan = Boolean.TRUE;
        } else {
            this.blackducksca_scan_full = null;
            this.blackduckscaIntelligentScan = null;
        }
    }

    @DataBoundSetter
    public void setBlackducksca_scan_failure_severities(String blackducksca_scan_failure_severities) {
        this.blackducksca_scan_failure_severities = Util.fixEmptyAndTrim(blackducksca_scan_failure_severities);
    }

    @DataBoundSetter
    public void setDetect_download_url(String detect_download_url) {
        this.detect_download_url = Util.fixEmptyAndTrim(detect_download_url);
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_create(Boolean blackducksca_reports_sarif_create) {
        this.blackducksca_reports_sarif_create = blackducksca_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_file_path(String blackducksca_reports_sarif_file_path) {
        this.blackducksca_reports_sarif_file_path = Util.fixEmptyAndTrim(blackducksca_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_groupSCAIssues(Boolean blackducksca_reports_sarif_groupSCAIssues) {
        this.blackducksca_reports_sarif_groupSCAIssues = this.blackducksca_reports_sarif_groupSCAIssues_temporary =
                blackducksca_reports_sarif_groupSCAIssues ? true : false;
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_severities(String blackducksca_reports_sarif_severities) {
        this.blackducksca_reports_sarif_severities = Util.fixEmptyAndTrim(blackducksca_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setBlackducksca_waitForScan(Boolean blackducksca_waitForScan) {
        this.blackducksca_waitForScan = this.blackducksca_waitForScan_actualValue = blackducksca_waitForScan;
    }

    @DataBoundSetter
    public void setDetect_search_depth(Integer detect_search_depth) {
        this.detect_search_depth = detect_search_depth;
    }

    @DataBoundSetter
    public void setDetect_config_path(String detect_config_path) {
        this.detect_config_path = Util.fixEmptyAndTrim(detect_config_path);
    }

    @DataBoundSetter
    public void setDetect_args(String detect_args) {
        this.detect_args = Util.fixEmptyAndTrim(detect_args);
    }

    @DataBoundSetter
    public void setDetect_execution_path(String detect_execution_path) {
        this.detect_execution_path = Util.fixEmptyAndTrim(detect_execution_path);
    }

    @DataBoundSetter
    public void setCoverity_url(String coverity_url) {
        this.coverity_url = coverity_url;
    }

    @DataBoundSetter
    public void setCoverity_user(String coverity_user) {
        this.coverity_user = coverity_user;
    }

    @DataBoundSetter
    public void setCoverity_passphrase(String coverity_passphrase) {
        this.coverity_passphrase = coverity_passphrase;
    }

    @DataBoundSetter
    public void setCoverity_project_name(String coverity_project_name) {
        this.coverity_project_name = Util.fixEmptyAndTrim(coverity_project_name);
    }

    @DataBoundSetter
    public void setCoverity_stream_name(String coverity_stream_name) {
        this.coverity_stream_name = Util.fixEmptyAndTrim(coverity_stream_name);
    }

    @DataBoundSetter
    public void setCoverity_policy_view(String coverity_policy_view) {
        this.coverity_policy_view = Util.fixEmptyAndTrim(coverity_policy_view);
    }

    @DataBoundSetter
    public void setCoverity_install_directory(String coverity_install_directory) {
        this.coverity_install_directory = coverity_install_directory;
    }

    @DataBoundSetter
    public void setCoverity_version(String coverity_version) {
        this.coverity_version = Util.fixEmptyAndTrim(coverity_version);
    }

    @DataBoundSetter
    public void setCoverity_local(Boolean coverity_local) {
        this.coverity_local = coverity_local ? true : null;
    }

    @DataBoundSetter
    public void setCoverity_build_command(String coverity_build_command) {
        this.coverity_build_command = Util.fixEmptyAndTrim(coverity_build_command);
    }

    @DataBoundSetter
    public void setCoverity_clean_command(String coverity_clean_command) {
        this.coverity_clean_command = Util.fixEmptyAndTrim(coverity_clean_command);
    }

    @DataBoundSetter
    public void setCoverity_config_path(String coverity_config_path) {
        this.coverity_config_path = Util.fixEmptyAndTrim(coverity_config_path);
    }

    @DataBoundSetter
    public void setCoverity_args(String coverity_args) {
        this.coverity_args = Util.fixEmptyAndTrim(coverity_args);
    }

    @DataBoundSetter
    public void setCoverity_execution_path(String coverity_execution_path) {
        this.coverity_execution_path = Util.fixEmptyAndTrim(coverity_execution_path);
    }

    @DataBoundSetter
    public void setCoverity_waitForScan(Boolean coverity_waitForScan) {
        this.coverity_waitForScan = this.coverity_waitForScan_actualValue = coverity_waitForScan;
    }

    @DataBoundSetter
    public void setPolaris_server_url(String polaris_server_url) {
        this.polaris_server_url = polaris_server_url;
    }

    @DataBoundSetter
    public void setPolaris_access_token(String polaris_access_token) {
        this.polaris_access_token = polaris_access_token;
    }

    @DataBoundSetter
    public void setPolaris_application_name(String polaris_application_name) {
        this.polaris_application_name = Util.fixEmptyAndTrim(polaris_application_name);
    }

    @DataBoundSetter
    public void setPolaris_project_name(String polaris_project_name) {
        this.polaris_project_name = Util.fixEmptyAndTrim(polaris_project_name);
    }

    @DataBoundSetter
    public void setPolaris_assessment_types(String polaris_assessment_types) {
        this.polaris_assessment_types = Util.fixEmptyAndTrim(polaris_assessment_types);
    }

    @DataBoundSetter
    public void setPolaris_branch_name(String polaris_branch_name) {
        this.polaris_branch_name = Util.fixEmptyAndTrim(polaris_branch_name);
    }

    @DataBoundSetter
    public void setPolaris_branch_parent_name(String polaris_branch_parent_name) {
        this.polaris_branch_parent_name = polaris_branch_parent_name;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_create(Boolean polaris_reports_sarif_create) {
        this.polaris_reports_sarif_create = polaris_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_file_path(String polaris_reports_sarif_file_path) {
        this.polaris_reports_sarif_file_path = Util.fixEmptyAndTrim(polaris_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_groupSCAIssues(Boolean polaris_reports_sarif_groupSCAIssues) {
        this.polaris_reports_sarif_groupSCAIssues = this.polaris_reports_sarif_groupSCAIssues_temporary =
                polaris_reports_sarif_groupSCAIssues ? true : false;
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_severities(String polaris_reports_sarif_severities) {
        this.polaris_reports_sarif_severities = Util.fixEmptyAndTrim(polaris_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setPolaris_reports_sarif_issue_types(String polaris_reports_sarif_issue_types) {
        this.polaris_reports_sarif_issue_types = Util.fixEmptyAndTrim(polaris_reports_sarif_issue_types);
    }

    @DataBoundSetter
    public void setBitbucket_username(String bitbucket_username) {
        this.bitbucket_username = bitbucket_username;
    }

    @DataBoundSetter
    public void setPolaris_assessment_mode(String polaris_assessment_mode) {
        this.polaris_assessment_mode = Util.fixEmptyAndTrim(polaris_assessment_mode);
    }

    @DataBoundSetter
    public void setPolaris_test_sca_type(String polaris_test_sca_type) {
        this.polaris_test_sca_type = Util.fixEmptyAndTrim(polaris_test_sca_type);
    }

    @DataBoundSetter
    public void setPolaris_test_sast_type(String polaris_test_sast_type) {
        this.polaris_test_sast_type = Util.fixEmptyAndTrim(polaris_test_sast_type);
    }

    @DataBoundSetter
    public void setPolaris_sca_search_depth(Integer polaris_sca_search_depth) {
        this.polaris_sca_search_depth = polaris_sca_search_depth;
    }

    @DataBoundSetter
    public void setPolaris_sca_config_path(String polaris_sca_config_path) {
        this.polaris_sca_config_path = Util.fixEmptyAndTrim(polaris_sca_config_path);
    }

    @DataBoundSetter
    public void setPolaris_sca_args(String polaris_sca_args) {
        this.polaris_sca_args = Util.fixEmptyAndTrim(polaris_sca_args);
    }

    @DataBoundSetter
    public void setPolaris_sast_build_command(String polaris_sast_build_command) {
        this.polaris_sast_build_command = Util.fixEmptyAndTrim(polaris_sast_build_command);
    }

    @DataBoundSetter
    public void setPolaris_sast_clean_command(String polaris_sast_clean_command) {
        this.polaris_sast_clean_command = Util.fixEmptyAndTrim(polaris_sast_clean_command);
    }

    @DataBoundSetter
    public void setPolaris_sast_config_path(String polaris_sast_config_path) {
        this.polaris_sast_config_path = Util.fixEmptyAndTrim(polaris_sast_config_path);
    }

    @DataBoundSetter
    public void setPolaris_sast_args(String polaris_sast_args) {
        this.polaris_sast_args = Util.fixEmptyAndTrim(polaris_sast_args);
    }

    @DataBoundSetter
    public void setPolaris_waitForScan(Boolean polaris_waitForScan) {
        this.polaris_waitForScan = this.polaris_waitForScan_actualValue = polaris_waitForScan;
    }

    @DataBoundSetter
    public void setProject_source_archive(String project_source_archive) {
        this.project_source_archive = Util.fixEmptyAndTrim(project_source_archive);
    }

    @DataBoundSetter
    public void setProject_source_preserveSymLinks(Boolean project_source_preserveSymLinks) {
        this.project_source_preserveSymLinks =
                this.project_source_preserveSymLinks_actualValue = project_source_preserveSymLinks ? true : null;
    }

    @DataBoundSetter
    public void setProject_source_excludes(String project_source_excludes) {
        this.project_source_excludes = Util.fixEmptyAndTrim(project_source_excludes);
    }

    @DataBoundSetter
    public void setProject_directory(String project_directory) {
        this.project_directory = Util.fixEmptyAndTrim(project_directory);
    }

    @DataBoundSetter
    public void setCoverity_project_directory(String coverity_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.coverity_project_directory = this.project_directory = Util.fixEmptyAndTrim(coverity_project_directory);
    }

    @DataBoundSetter
    public void setBlackducksca_project_directory(String blackducksca_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase()))
            this.blackducksca_project_directory =
                    this.project_directory = Util.fixEmptyAndTrim(blackducksca_project_directory);
    }

    @DataBoundSetter
    public void setPolaris_project_directory(String polaris_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.polaris_project_directory = this.project_directory = Util.fixEmptyAndTrim(polaris_project_directory);
    }

    @DataBoundSetter
    public void setSrm_project_directory(String srm_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.srm_project_directory = this.project_directory = Util.fixEmptyAndTrim(srm_project_directory);
    }

    @DataBoundSetter
    public void setBitbucket_token(String bitbucket_token) {
        this.bitbucket_token = bitbucket_token;
    }

    @DataBoundSetter
    public void setGithub_token(String github_token) {
        this.github_token = github_token;
    }

    @DataBoundSetter
    public void setGitlab_token(String gitlab_token) {
        this.gitlab_token = gitlab_token;
    }

    @DataBoundSetter
    public void setBridgecli_download_url(String bridgecli_download_url) {
        this.bridgecli_download_url = bridgecli_download_url;
    }

    @DataBoundSetter
    public void setBridgecli_download_version(String bridgecli_download_version) {
        this.bridgecli_download_version = bridgecli_download_version;
    }

    @DataBoundSetter
    public void setBridgecli_install_directory(String bridgecli_install_directory) {
        this.bridgecli_install_directory = bridgecli_install_directory;
    }

    @DataBoundSetter
    public void setInclude_diagnostics(Boolean include_diagnostics) {
        this.include_diagnostics = include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setCoverity_include_diagnostics(Boolean coverity_include_diagnostics) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.include_diagnostics = coverity_include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setBlackducksca_include_diagnostics(Boolean blackducksca_include_diagnostics) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase()))
            this.include_diagnostics = blackducksca_include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setPolaris_include_diagnostics(Boolean polaris_include_diagnostics) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.include_diagnostics = polaris_include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setSrm_include_diagnostics(Boolean srm_include_diagnostics) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.include_diagnostics = srm_include_diagnostics ? true : null;
    }

    @DataBoundSetter
    public void setMark_build_status(String mark_build_status) {
        this.mark_build_status = mark_build_status;
    }

    @DataBoundSetter
    public void setCoverity_mark_build_status(String coverity_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.coverity_mark_build_status = this.mark_build_status = Util.fixEmptyAndTrim(coverity_mark_build_status);
    }

    @DataBoundSetter
    public void setBlackducksca_mark_build_status(String blackducksca_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase()))
            this.blackducksca_mark_build_status =
                    this.mark_build_status = Util.fixEmptyAndTrim(blackducksca_mark_build_status);
    }

    @DataBoundSetter
    public void setPolaris_mark_build_status(String polaris_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.polaris_mark_build_status = this.mark_build_status = Util.fixEmptyAndTrim(polaris_mark_build_status);
    }

    @DataBoundSetter
    public void setSrm_mark_build_status(String srm_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.srm_mark_build_status = this.mark_build_status = Util.fixEmptyAndTrim(srm_mark_build_status);
    }

    @DataBoundSetter
    public void setSrm_url(String srm_url) {
        this.srm_url = srm_url;
    }

    @DataBoundSetter
    public void setSrm_apikey(String srm_apikey) {
        this.srm_apikey = srm_apikey;
    }

    @DataBoundSetter
    public void setSrm_assessment_types(String srm_assessment_types) {
        this.srm_assessment_types = Util.fixEmptyAndTrim(srm_assessment_types);
    }

    @DataBoundSetter
    public void setSrm_project_name(String srm_project_name) {
        this.srm_project_name = Util.fixEmptyAndTrim(srm_project_name);
    }

    @DataBoundSetter
    public void setSrm_project_id(String srm_project_id) {
        this.srm_project_id = Util.fixEmptyAndTrim(srm_project_id);
    }

    @DataBoundSetter
    public void setSrm_branch_name(String srm_branch_name) {
        this.srm_branch_name = Util.fixEmptyAndTrim(srm_branch_name);
    }

    @DataBoundSetter
    public void setSrm_branch_parent(String srm_branch_parent) {
        this.srm_branch_parent = Util.fixEmptyAndTrim(srm_branch_parent);
    }

    @DataBoundSetter
    public void setSrm_sca_search_depth(Integer srm_sca_search_depth) {
        this.srm_sca_search_depth = srm_sca_search_depth;
    }

    @DataBoundSetter
    public void setSrm_sca_config_path(String srm_sca_config_path) {
        this.srm_sca_config_path = srm_sca_config_path;
    }

    @DataBoundSetter
    public void setSrm_sca_args(String srm_sca_args) {
        this.srm_sca_args = srm_sca_args;
    }

    @DataBoundSetter
    public void setSrm_sast_build_command(String srm_sast_build_command) {
        this.srm_sast_build_command = srm_sast_build_command;
    }

    @DataBoundSetter
    public void setSrm_sast_clean_command(String srm_sast_clean_command) {
        this.srm_sast_clean_command = srm_sast_clean_command;
    }

    @DataBoundSetter
    public void setSrm_sast_config_path(String srm_sast_config_path) {
        this.srm_sast_config_path = srm_sast_config_path;
    }

    @DataBoundSetter
    public void setSrm_sast_args(String srm_sast_args) {
        this.srm_sast_args = srm_sast_args;
    }

    @DataBoundSetter
    public void setSrm_waitForScan(Boolean srm_waitForScan) {
        this.srm_waitForScan = this.srm_waitForScan_actualValue = srm_waitForScan;
    }

    private Map<String, Object> getParametersMap(FilePath workspace, TaskListener listener)
            throws PluginExceptionHandler {
        return ParameterMappingService.preparePipelineParametersMap(
                this, ParameterMappingService.getGlobalConfigurationValues(workspace, listener), listener);
    }

    @Override
    public void perform(
            @NonNull Run<?, ?> run,
            @NonNull FilePath workspace,
            @NonNull EnvVars envVars,
            @NonNull Launcher launcher,
            @NonNull TaskListener listener) {
        int exitCode = 0;
        String undefinedErrorMessage = null;
        Exception unknownException = new Exception();
        LoggerWrapper logger = new LoggerWrapper(listener);
        Map<String, Object> scanparametersMap = null;

        logger.info(
                "**************************** START EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");
        try {
            scanparametersMap = getParametersMap(workspace, listener);
            SecurityScanner securityScanner = new SecurityScanner(run, listener, launcher, workspace, envVars);
            ScanInitializer scanInitializer = new ScanInitializer(securityScanner, workspace, envVars, listener);

            Map<String, Object> scanParamMapExp = handleScanParametersEnvVarsResolution(scanparametersMap, envVars);

            exitCode = scanInitializer.initializeScanner(scanParamMapExp);
        } catch (Exception e) {
            if (e instanceof PluginExceptionHandler) {
                exitCode = ((PluginExceptionHandler) e).getCode();
            } else {
                exitCode = ErrorCode.UNDEFINED_PLUGIN_ERROR;
                undefinedErrorMessage = e.getMessage();
                unknownException = e;
            }
        } finally {
            String exitMessage = ExceptionMessages.getErrorMessage(exitCode, undefinedErrorMessage);
            if (exitMessage != null) {
                if (exitCode == 0) {
                    logger.info(exitMessage);
                } else {
                    logger.error(exitMessage);
                }
            }

            handleExitCode(run, logger, exitCode, exitMessage, unknownException);
        }
    }

    public Map<String, Object> handleScanParametersEnvVarsResolution(
            Map<String, Object> scanparametersMap, EnvVars envVars) {
        if (scanparametersMap.isEmpty() || envVars.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Object> updatedMap = new HashMap<>();
        scanparametersMap.forEach((key, value) -> {
            if (value instanceof String) {
                updatedMap.put(key, envVars.expand((String) value));
            } else {
                updatedMap.put(key, value);
            }
        });
        return updatedMap;
    }

    private void handleExitCode(Run<?, ?> run, LoggerWrapper logger, int exitCode, String exitMessage, Exception e) {
        if (exitCode != ErrorCode.BRIDGE_BUILD_BREAK && !Utility.isStringNullOrBlank(this.getMark_build_status())) {
            logger.info("Marking build status as " + this.getMark_build_status() + " is ignored since exit code is: "
                    + exitCode);
        }

        if (exitCode == ErrorCode.SCAN_SUCCESSFUL) {
            logger.info(
                    "**************************** END EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");
        } else {
            Result result = ParameterMappingService.getBuildResultIfIssuesAreFound(
                    exitCode, this.getMark_build_status(), logger);

            if (result != null) {
                logger.info("Marking build as " + result + " since issues are present");
                run.setResult(result);
            }

            logger.info(
                    "**************************** END EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");

            if (result == null) {
                if (exitCode == ErrorCode.UNDEFINED_PLUGIN_ERROR) {
                    throw new RuntimeException(new ScannerException(exitMessage, e));
                } else {
                    throw new RuntimeException(new PluginExceptionHandler(exitMessage));
                }
            }
        }
    }

    @Extension
    public static class Descriptor extends BuildStepDescriptor<Builder> {

        @Override
        public String getDisplayName() {
            return ApplicationConstants.DISPLAY_NAME_BLACKDUCK;
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return jobType.isAssignableFrom(FreeStyleProject.class);
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillProductItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(new ListBoxModel.Option(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "select"));
            items.addAll(ParameterMappingService.getSecurityProductItems());
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillBlackducksca_mark_build_statusItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "");
            items.addAll(ParameterMappingService.getMarkBuildStatusItems());
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillPolaris_mark_build_statusItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "");
            items.addAll(ParameterMappingService.getMarkBuildStatusItems());
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillCoverity_mark_build_statusItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "");
            items.addAll(ParameterMappingService.getMarkBuildStatusItems());
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillSrm_mark_build_statusItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, "");
            items.addAll(ParameterMappingService.getMarkBuildStatusItems());
            return items;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillPolaris_assessment_modeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(new ListBoxModel.Option(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, ""));
            items.add(new ListBoxModel.Option("CI", "CI"));
            items.add(new ListBoxModel.Option("SOURCE_UPLOAD", "SOURCE_UPLOAD"));
            return items;
        }
    }
}
