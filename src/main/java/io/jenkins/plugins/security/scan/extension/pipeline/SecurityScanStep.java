package io.jenkins.plugins.security.scan.extension.pipeline;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.*;
import hudson.model.Node;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource;
import io.jenkins.plugins.security.scan.ScanInitializer;
import io.jenkins.plugins.security.scan.SecurityScanner;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.exception.ScannerException;
import io.jenkins.plugins.security.scan.extension.SecurityScan;
import io.jenkins.plugins.security.scan.global.*;
import io.jenkins.plugins.security.scan.global.enums.SecurityProduct;
import io.jenkins.plugins.security.scan.service.ParameterMappingService;
import io.jenkins.plugins.security.scan.service.scm.SCMRepositoryService;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jenkins.scm.api.SCMSource;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.jenkinsci.plugins.workflow.actions.WarningAction;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.steps.*;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class SecurityScanStep extends Step
        implements SecurityScan, PrCommentScan, FixPrScan, ReturnStatusScan, NetworkParams, Serializable {
    private static final long serialVersionUID = 6294070801130995534L;

    private String product;

    private String blackducksca_url;
    private transient String blackducksca_token;
    private String blackducksca_scan_failure_severities;
    private Boolean blackducksca_prComment_enabled;
    private Boolean blackducksca_prComment_enabled_actualValue;
    private Boolean blackducksca_fixpr_enabled;
    private Boolean blackducksca_fixpr_enabled_actualValue;
    private String blackducksca_fixpr_filter_severities;
    private String blackducksca_fixpr_useUpgradeGuidance;
    private Integer blackducksca_fixpr_maxCount;
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

    // Deprecated blackduck parameters
    private String blackduck_url;
    private transient String blackduck_token;
    private String blackduck_install_directory;
    private Boolean blackduck_scan_full;
    private Boolean blackduckIntelligentScan;
    private String blackduck_scan_failure_severities;
    private Boolean blackduck_prComment_enabled;
    private Boolean blackduck_prComment_enabled_actualValue;
    private String blackduck_download_url;
    private Boolean blackduck_reports_sarif_create;
    private String blackduck_reports_sarif_file_path;
    private Boolean blackduck_reports_sarif_groupSCAIssues;
    private String blackduck_reports_sarif_severities;
    private Boolean blackduck_reports_sarif_groupSCAIssues_temporary;
    private Integer blackduck_search_depth;
    private String blackduck_config_path;
    private String blackduck_args;
    private String blackduck_execution_path;
    private Boolean blackduck_waitForScan;
    private Boolean blackduck_waitForScan_actualValue;

    private String coverity_url;
    private String coverity_user;
    private transient String coverity_passphrase;
    private String coverity_project_name;
    private String coverity_stream_name;
    private String coverity_policy_view;
    private String coverity_install_directory;
    private Boolean coverity_prComment_enabled;
    private Boolean coverity_prComment_enabled_actualValue;
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
    private Boolean polaris_prComment_enabled;
    private Boolean polaris_prComment_enabled_actualValue;
    private String polaris_prComment_severities;
    private Boolean polaris_reports_sarif_create;
    private String polaris_reports_sarif_file_path;
    private String polaris_reports_sarif_issue_types;
    private Boolean polaris_reports_sarif_groupSCAIssues;
    private String polaris_reports_sarif_severities;
    private Boolean polaris_reports_sarif_groupSCAIssues_temporary;
    private String polaris_assessment_mode;
    private String polaris_test_sca_type;
    private String polaris_test_sast_type;
    private String project_source_archive;
    private String project_source_excludes;
    private Boolean project_source_preserveSymLinks;
    private Boolean project_source_preserveSymLinks_actualValue;
    private String project_directory;
    private String coverity_project_directory;
    private String blackducksca_project_directory;
    private String polaris_project_directory;
    private String srm_project_directory;
    private Boolean polaris_waitForScan;
    private Boolean polaris_waitForScan_actualValue;

    private String srm_url;
    private transient String srm_apikey;
    private String srm_assessment_types;
    private String srm_project_name;
    private String srm_project_id;
    private String srm_branch_name;
    private String srm_branch_parent;
    private Boolean srm_waitForScan;
    private Boolean srm_waitForScan_actualValue;

    private String bitbucket_username;
    private transient String bitbucket_token;
    private transient String github_token;
    private transient String gitlab_token;

    private String bridgecli_download_url;
    private String bridgecli_download_version;
    private String bridgecli_install_directory;
    private String synopsys_bridge_download_url;
    private String synopsys_bridge_download_version;
    private String synopsys_bridge_install_directory;
    private Boolean include_diagnostics;
    private Boolean coverity_include_diagnostics;
    private Boolean blackducksca_include_diagnostics;
    private Boolean polaris_include_diagnostics;
    private Boolean srm_include_diagnostics;
    private Boolean network_airgap;
    private String network_ssl_cert_file;
    private Boolean network_ssl_trustAll;
    /*
    By default, the plugin will always return a status code even if there is error.
     */
    private Boolean return_status = true;
    private String mark_build_status;
    private String blackducksca_mark_build_status;
    private String coverity_mark_build_status;
    private String polaris_mark_build_status;
    private String srm_mark_build_status;

    @DataBoundConstructor
    public SecurityScanStep() {
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

    public Boolean isBlackducksca_prComment_enabled() {
        return blackducksca_prComment_enabled;
    }

    public Boolean isBlackducksca_prComment_enabled_actualValue() {
        return blackducksca_prComment_enabled_actualValue;
    }

    public Boolean isBlackducksca_fixpr_enabled() {
        return blackducksca_fixpr_enabled;
    }

    public Boolean isBlackducksca_fixpr_enabled_actualValue() {
        return blackducksca_fixpr_enabled_actualValue;
    }

    public String getBlackducksca_fixpr_filter_severities() {
        return blackducksca_fixpr_filter_severities;
    }

    public String getBlackducksca_fixpr_useUpgradeGuidance() {
        return blackducksca_fixpr_useUpgradeGuidance;
    }

    public Integer getBlackducksca_fixpr_maxCount() {
        return blackducksca_fixpr_maxCount;
    }

    public String getDetect_download_url() {
        return detect_download_url;
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

    public String getBlackduck_url() {
        return blackduck_url;
    }

    public String getBlackduck_token() {
        return blackduck_token;
    }

    public String getBlackduck_install_directory() {
        return blackduck_install_directory;
    }

    public Boolean isBlackduck_scan_full() {
        return blackduck_scan_full;
    }

    public Boolean isBlackduckIntelligentScan() {
        return blackduckIntelligentScan;
    }

    public String getBlackduck_scan_failure_severities() {
        return blackduck_scan_failure_severities;
    }

    public Boolean isBlackduck_prComment_enabled() {
        return blackduck_prComment_enabled;
    }

    public Boolean isBlackduck_prComment_enabled_actualValue() {
        return blackduck_prComment_enabled_actualValue;
    }

    public String getBlackduck_download_url() {
        return blackduck_download_url;
    }

    public Integer getBlackduck_search_depth() {
        return blackduck_search_depth;
    }

    public String getBlackduck_config_path() {
        return blackduck_config_path;
    }

    public String getBlackduck_args() {
        return blackduck_args;
    }

    public String getBlackduck_execution_path() {
        return blackduck_execution_path;
    }

    public Boolean isBlackduck_reports_sarif_create() {
        return blackduck_reports_sarif_create;
    }

    public String getBlackduck_reports_sarif_file_path() {
        return blackduck_reports_sarif_file_path;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues() {
        return blackduck_reports_sarif_groupSCAIssues;
    }

    public String getBlackduck_reports_sarif_severities() {
        return blackduck_reports_sarif_severities;
    }

    public Boolean isBlackduck_reports_sarif_groupSCAIssues_temporary() {
        return blackduck_reports_sarif_groupSCAIssues_temporary;
    }

    public Boolean isBlackduck_waitForScan() {
        return blackduck_waitForScan;
    }

    public Boolean isBlackduck_waitForScan_actualValue() {
        return blackduck_waitForScan_actualValue;
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

    public Boolean isCoverity_prComment_enabled() {
        return coverity_prComment_enabled;
    }

    public Boolean isCoverity_prComment_enabled_actualValue() {
        return coverity_prComment_enabled_actualValue;
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

    public Boolean isPolaris_prComment_enabled() {
        return polaris_prComment_enabled;
    }

    public Boolean isPolaris_prComment_enabled_actualValue() {
        return polaris_prComment_enabled_actualValue;
    }

    public String getPolaris_prComment_severities() {
        return polaris_prComment_severities;
    }

    public String getPolaris_test_sca_type() {
        return polaris_test_sca_type;
    }

    public String getPolaris_test_sast_type() {
        return polaris_test_sast_type;
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

    public String getProject_source_archive() {
        return project_source_archive;
    }

    public Boolean isProject_source_preserveSymLinks() {
        return project_source_preserveSymLinks;
    }

    public Boolean isProject_source_preserveSymLinks_actualValue() {
        return project_source_preserveSymLinks_actualValue;
    }

    public Boolean isPolaris_waitForScan() {
        return polaris_waitForScan;
    }

    public Boolean isPolaris_waitForScan_actualValue() {
        return polaris_waitForScan_actualValue;
    }

    public String getProject_source_excludes() {
        return project_source_excludes;
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
        return synopsys_bridge_download_url;
    }

    public String getSynopsys_bridge_download_version() {
        return synopsys_bridge_download_version;
    }

    public String getSynopsys_bridge_install_directory() {
        return synopsys_bridge_install_directory;
    }

    public Boolean isInclude_diagnostics() {
        return include_diagnostics;
    }

    @Nullable
    public Boolean isCoverity_include_diagnostics() {
        return null;
    }

    @Nullable
    public Boolean isBlackducksca_include_diagnostics() {
        return null;
    }

    @Nullable
    public Boolean isPolaris_include_diagnostics() {
        return null;
    }

    @Nullable
    public Boolean isSrm_include_diagnostics() {
        return null;
    }

    public Boolean isNetwork_airgap() {
        return network_airgap;
    }

    public String getNetwork_ssl_cert_file() {
        return network_ssl_cert_file;
    }

    public Boolean isNetwork_ssl_trustAll() {
        return network_ssl_trustAll;
    }

    public Boolean isReturn_status() {
        return return_status;
    }

    public String getMark_build_status() {
        return mark_build_status;
    }

    @Nullable
    public String getBlackducksca_mark_build_status() {
        return null;
    }

    @Nullable
    public String getCoverity_mark_build_status() {
        return null;
    }

    @Nullable
    public String getPolaris_mark_build_status() {
        return null;
    }

    @Nullable
    public String getSrm_mark_build_status() {
        return null;
    }

    public String getProject_directory() {
        return project_directory;
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

    public Boolean isSrm_waitForScan() {
        return srm_waitForScan;
    }

    public Boolean isSrm_waitForScan_actualValue() {
        return srm_waitForScan_actualValue;
    }

    // Returning the null value because if we return any other value, blackduck_project_directory field will be visible
    // in the pipeline syntax script
    @Nullable
    public String getBlackducksca_project_directory() {
        return null;
    }

    // Returning the null value because if we return any other value, coverity_project_directory field will be visible
    // in the pipeline syntax script
    @Nullable
    public String getCoverity_project_directory() {
        return null;
    }

    // Returning the null value because if we return any other value, polaris_project_directory field will be visible in
    // the pipeline syntax script
    @Nullable
    public String getPolaris_project_directory() {
        return null;
    }

    // Returning the null value because if we return any other value, srm_project_directory field will be visible in
    // the pipeline syntax script
    @Nullable
    public String getSrm_project_directory() {
        return null;
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
    public void setDetect_install_directory(String blackducksca_install_directory) {
        this.detect_install_directory = blackducksca_install_directory;
    }

    @DataBoundSetter
    public void setBlackducksca_scan_full(Boolean blackducksca_scan_full) {
        if (blackducksca_scan_full) {
            this.blackduckscaIntelligentScan = true;
        }
        if (!blackducksca_scan_full) {
            this.blackduckscaIntelligentScan = false;
        }
        this.blackducksca_scan_full = blackducksca_scan_full ? true : null;
    }

    @DataBoundSetter
    public void setBlackducksca_scan_failure_severities(String blackducksca_scan_failure_severities) {
        this.blackducksca_scan_failure_severities = Util.fixEmptyAndTrim(blackducksca_scan_failure_severities);
    }

    @DataBoundSetter
    public void setBlackducksca_prComment_enabled(Boolean blackducksca_prComment_enabled) {
        this.blackducksca_prComment_enabled = blackducksca_prComment_enabled ? true : null;
        this.blackducksca_prComment_enabled_actualValue = blackducksca_prComment_enabled ? true : false;
    }

    @DataBoundSetter
    public void setBlackducksca_fixpr_enabled(Boolean blackducksca_fixpr_enabled) {
        this.blackducksca_fixpr_enabled = blackducksca_fixpr_enabled ? true : null;
        this.blackducksca_fixpr_enabled_actualValue = blackducksca_fixpr_enabled ? true : false;
    }

    @DataBoundSetter
    public void setBlackducksca_fixpr_filter_severities(String blackducksca_fixpr_filter_severities) {
        this.blackducksca_fixpr_filter_severities = Util.fixEmptyAndTrim(blackducksca_fixpr_filter_severities);
    }

    @DataBoundSetter
    public void setBlackducksca_fixpr_useUpgradeGuidance(String blackducksca_fixpr_useUpgradeGuidance) {
        this.blackducksca_fixpr_useUpgradeGuidance = Util.fixEmptyAndTrim(blackducksca_fixpr_useUpgradeGuidance);
    }

    @DataBoundSetter
    public void setBlackducksca_fixpr_maxCount(Integer blackducksca_fixpr_maxCount) {
        this.blackducksca_fixpr_maxCount = blackducksca_fixpr_maxCount;
    }

    @DataBoundSetter
    public void setDetect_download_url(String detect_download_url) {
        this.detect_download_url = Util.fixEmptyAndTrim(detect_download_url);
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
    public void setBlackducksca_reports_sarif_create(Boolean blackducksca_reports_sarif_create) {
        this.blackducksca_reports_sarif_create = blackducksca_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_file_path(String blackducksca_reports_sarif_file_path) {
        this.blackducksca_reports_sarif_file_path = Util.fixEmptyAndTrim(blackducksca_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_groupSCAIssues(Boolean blackducksca_reports_sarif_groupSCAIssues) {
        this.blackducksca_reports_sarif_groupSCAIssues = blackducksca_reports_sarif_groupSCAIssues ? true : null;
        this.blackducksca_reports_sarif_groupSCAIssues_temporary =
                blackducksca_reports_sarif_groupSCAIssues ? true : false;
    }

    @DataBoundSetter
    public void setBlackducksca_reports_sarif_severities(String blackducksca_reports_sarif_severities) {
        this.blackducksca_reports_sarif_severities = Util.fixEmptyAndTrim(blackducksca_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setBlackducksca_waitForScan(Boolean blackducksca_waitForScan) {
        this.blackducksca_waitForScan = blackducksca_waitForScan ? true : null;
        this.blackducksca_waitForScan_actualValue = blackducksca_waitForScan ? true : false;
    }

    @DataBoundSetter
    public void setBlackduck_url(String blackduck_url) {
        this.blackduck_url = blackduck_url;
    }

    @DataBoundSetter
    public void setBlackduck_token(String blackduck_token) {
        this.blackduck_token = blackduck_token;
    }

    @DataBoundSetter
    public void setBlackduck_install_directory(String blackduck_install_directory) {
        this.blackduck_install_directory = blackduck_install_directory;
    }

    @DataBoundSetter
    public void setBlackduck_scan_full(Boolean blackduck_scan_full) {
        if (blackduck_scan_full) {
            this.blackduckIntelligentScan = true;
        }
        if (!blackduck_scan_full) {
            this.blackduckIntelligentScan = false;
        }
        this.blackduck_scan_full = blackduck_scan_full ? true : null;
    }

    @DataBoundSetter
    public void setBlackduck_scan_failure_severities(String blackduck_scan_failure_severities) {
        this.blackduck_scan_failure_severities = Util.fixEmptyAndTrim(blackduck_scan_failure_severities);
    }

    @DataBoundSetter
    public void setBlackduck_prComment_enabled(Boolean blackduck_prComment_enabled) {
        this.blackduck_prComment_enabled = blackduck_prComment_enabled ? true : null;
        this.blackduck_prComment_enabled_actualValue = blackduck_prComment_enabled ? true : false;
    }

    @DataBoundSetter
    public void setBlackduck_download_url(String blackduck_download_url) {
        this.blackduck_download_url = Util.fixEmptyAndTrim(blackduck_download_url);
    }

    @DataBoundSetter
    public void setBlackduck_search_depth(Integer blackduck_search_depth) {
        this.blackduck_search_depth = blackduck_search_depth;
    }

    @DataBoundSetter
    public void setBlackduck_config_path(String blackduck_config_path) {
        this.blackduck_config_path = Util.fixEmptyAndTrim(blackduck_config_path);
    }

    @DataBoundSetter
    public void setBlackduck_args(String blackduck_args) {
        this.blackduck_args = Util.fixEmptyAndTrim(blackduck_args);
    }

    @DataBoundSetter
    public void setBlackduck_execution_path(String blackduck_execution_path) {
        this.blackduck_execution_path = Util.fixEmptyAndTrim(blackduck_execution_path);
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_create(Boolean blackduck_reports_sarif_create) {
        this.blackduck_reports_sarif_create = blackduck_reports_sarif_create ? true : null;
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_file_path(String blackduck_reports_sarif_file_path) {
        this.blackduck_reports_sarif_file_path = Util.fixEmptyAndTrim(blackduck_reports_sarif_file_path);
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_groupSCAIssues(Boolean blackduck_reports_sarif_groupSCAIssues) {
        this.blackduck_reports_sarif_groupSCAIssues = blackduck_reports_sarif_groupSCAIssues ? true : null;
        this.blackduck_reports_sarif_groupSCAIssues_temporary = blackduck_reports_sarif_groupSCAIssues ? true : false;
    }

    @DataBoundSetter
    public void setBlackduck_reports_sarif_severities(String blackduck_reports_sarif_severities) {
        this.blackduck_reports_sarif_severities = Util.fixEmptyAndTrim(blackduck_reports_sarif_severities);
    }

    @DataBoundSetter
    public void setBlackduck_waitForScan(Boolean blackduck_waitForScan) {
        this.blackduck_waitForScan = blackduck_waitForScan ? true : null;
        this.blackduck_waitForScan_actualValue = blackduck_waitForScan ? true : false;
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
    public void setCoverity_prComment_enabled(Boolean coverity_prComment_enabled) {
        this.coverity_prComment_enabled = coverity_prComment_enabled ? true : null;
        this.coverity_prComment_enabled_actualValue = coverity_prComment_enabled ? true : false;
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
        this.coverity_waitForScan = coverity_waitForScan ? true : null;
        this.coverity_waitForScan_actualValue = coverity_waitForScan ? true : false;
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
        this.polaris_branch_parent_name = Util.fixEmptyAndTrim(polaris_branch_parent_name);
    }

    @DataBoundSetter
    public void setPolaris_prComment_enabled(Boolean polaris_prComment_enabled) {
        this.polaris_prComment_enabled = polaris_prComment_enabled ? true : null;
        this.polaris_prComment_enabled_actualValue = polaris_prComment_enabled ? true : false;
    }

    @DataBoundSetter
    public void setPolaris_prComment_severities(String polaris_prComment_severities) {
        this.polaris_prComment_severities = Util.fixEmptyAndTrim(polaris_prComment_severities);
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
    public void setPolaris_assessment_mode(String polaris_assessment_mode) {
        this.polaris_assessment_mode = Util.fixEmptyAndTrim(polaris_assessment_mode);
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
        this.polaris_reports_sarif_groupSCAIssues = polaris_reports_sarif_groupSCAIssues ? true : null;
        this.polaris_reports_sarif_groupSCAIssues_temporary = polaris_reports_sarif_groupSCAIssues ? true : false;
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
    public void setProject_source_archive(String project_source_archive) {
        this.project_source_archive = Util.fixEmptyAndTrim(project_source_archive);
    }

    @DataBoundSetter
    public void setProject_source_preserveSymLinks(Boolean project_source_preserveSymLinks) {
        this.project_source_preserveSymLinks = project_source_preserveSymLinks ? true : null;
        this.project_source_preserveSymLinks_actualValue = project_source_preserveSymLinks;
    }

    @DataBoundSetter
    public void setProject_source_excludes(String project_source_excludes) {
        this.project_source_excludes = Util.fixEmptyAndTrim(project_source_excludes);
    }

    @DataBoundSetter
    public void setPolaris_waitForScan(Boolean polaris_waitForScan) {
        this.polaris_waitForScan = polaris_waitForScan ? true : null;
        this.polaris_waitForScan_actualValue = polaris_waitForScan ? true : false;
    }

    @DataBoundSetter
    public void setSrm_url(String srm_url) {
        this.srm_url = srm_url;
    }

    @DataBoundSetter
    public void setSrm_apikey(String srm_apikey) {
        this.srm_apikey = Util.fixEmptyAndTrim(srm_apikey);
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
    public void setSrm_waitForScan(Boolean srm_waitForScan) {
        this.srm_waitForScan = srm_waitForScan ? true : null;
        this.srm_waitForScan_actualValue = srm_waitForScan ? true : false;
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
    public void setProject_directory(String project_directory) {
        this.project_directory = Util.fixEmptyAndTrim(project_directory);
    }

    @DataBoundSetter
    public void setCoverity_project_directory(String coverity_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.project_directory = Util.fixEmptyAndTrim(coverity_project_directory);
    }

    @DataBoundSetter
    public void setBlackducksca_project_directory(String blackducksca_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase()))
            this.project_directory = Util.fixEmptyAndTrim(blackducksca_project_directory);
    }

    @DataBoundSetter
    public void setPolaris_project_directory(String polaris_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.project_directory = Util.fixEmptyAndTrim(polaris_project_directory);
    }

    @DataBoundSetter
    public void setSrm_project_directory(String srm_project_directory) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.project_directory = Util.fixEmptyAndTrim(srm_project_directory);
    }

    @DataBoundSetter
    public void setBitbucket_username(String bitbucket_username) {
        this.bitbucket_username = bitbucket_username;
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
    public void setSynopsys_bridge_download_url(String synopsys_bridge_download_url) {
        this.synopsys_bridge_download_url = synopsys_bridge_download_url;
    }

    @DataBoundSetter
    public void setSynopsys_bridge_download_version(String synopsys_bridge_download_version) {
        this.synopsys_bridge_download_version = synopsys_bridge_download_version;
    }

    @DataBoundSetter
    public void setSynopsys_bridge_install_directory(String synopsys_bridge_install_directory) {
        this.synopsys_bridge_install_directory = synopsys_bridge_install_directory;
    }

    @DataBoundSetter
    public void setNetwork_airgap(Boolean network_airgap) {
        this.network_airgap = network_airgap ? true : null;
    }

    @DataBoundSetter
    public void setNetwork_ssl_cert_file(String network_ssl_cert_file) {
        this.network_ssl_cert_file = network_ssl_cert_file;
    }

    @DataBoundSetter
    public void setNetwork_ssl_trustAll(Boolean network_ssl_trustAll) {
        this.network_ssl_trustAll = network_ssl_trustAll;
    }

    @DataBoundSetter
    public void setReturn_status(Boolean return_status) {
        this.return_status = return_status;
    }

    @DataBoundSetter
    public void setMark_build_status(String mark_build_status) {
        this.mark_build_status = Util.fixEmptyAndTrim(mark_build_status);
    }

    @DataBoundSetter
    public void setCoverity_mark_build_status(String coverity_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.COVERITY.name().toLowerCase()))
            this.mark_build_status = Util.fixEmptyAndTrim(coverity_mark_build_status);
    }

    @DataBoundSetter
    public void setBlackducksca_mark_build_status(String blackducksca_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.BLACKDUCKSCA.name().toLowerCase()))
            this.mark_build_status = Util.fixEmptyAndTrim(blackducksca_mark_build_status);
    }

    @DataBoundSetter
    public void setPolaris_mark_build_status(String polaris_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.POLARIS.name().toLowerCase()))
            this.mark_build_status = Util.fixEmptyAndTrim(polaris_mark_build_status);
    }

    @DataBoundSetter
    public void setSrm_mark_build_status(String srm_mark_build_status) {
        if (getProduct().contentEquals(SecurityProduct.SRM.name().toLowerCase()))
            this.mark_build_status = Util.fixEmptyAndTrim(srm_mark_build_status);
    }

    private Map<String, Object> getParametersMap(FilePath workspace, TaskListener listener)
            throws PluginExceptionHandler {
        return ParameterMappingService.preparePipelineParametersMap(
                this, ParameterMappingService.getGlobalConfigurationValues(workspace, listener), listener);
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new Execution(context);
    }

    @Extension(optional = true)
    public static final class DescriptorImpl extends StepDescriptor {
        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return new HashSet<>(Arrays.asList(
                    Run.class, TaskListener.class, EnvVars.class, FilePath.class, Launcher.class, Node.class));
        }

        @Override
        public String getFunctionName() {
            return ApplicationConstants.PIPELINE_STEP_NAME;
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return ApplicationConstants.DISPLAY_NAME_BLACKDUCK;
        }

        @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
        public ListBoxModel doFillProductItems() {
            ListBoxModel items = new ListBoxModel();
            items.add(new Option(ApplicationConstants.DEFAULT_DROPDOWN_OPTION_NAME, ""));
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

    public class Execution extends SynchronousNonBlockingStepExecution<Integer> {
        private static final long serialVersionUID = -2514079516220990421L;
        private final transient Run<?, ?> run;
        private final transient Launcher launcher;
        private final transient FlowNode flowNode;

        @SuppressFBWarnings("SE_TRANSIENT_FIELD_NOT_RESTORED")
        private final transient TaskListener listener;

        @SuppressFBWarnings("SE_TRANSIENT_FIELD_NOT_RESTORED")
        private final transient EnvVars envVars;

        @SuppressFBWarnings("SE_TRANSIENT_FIELD_NOT_RESTORED")
        private final transient FilePath workspace;

        protected Execution(@Nonnull StepContext context) throws InterruptedException, IOException {
            super(context);
            run = context.get(Run.class);
            listener = context.get(TaskListener.class);
            envVars = context.get(EnvVars.class);
            workspace = context.get(FilePath.class);
            launcher = context.get(Launcher.class);
            flowNode = context.get(FlowNode.class);
        }

        @Override
        protected Integer run() throws PluginExceptionHandler, ScannerException {
            LoggerWrapper logger = new LoggerWrapper(listener);
            int exitCode = 0;
            String undefinedErrorMessage = null;
            Exception unknownException = new Exception();

            logger.println(
                    "**************************** START EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");

            Map<String, Object> scanparametersMap = getParametersMap(workspace, listener);

            try {
                verifyRequiredPlugins(logger, envVars);

                SecurityScanner securityScanner = new SecurityScanner(run, listener, launcher, workspace, envVars);
                ScanInitializer scanInitializer = new ScanInitializer(securityScanner, workspace, envVars, listener);

                exitCode = scanInitializer.initializeScanner(scanparametersMap);
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

                handleExitCode(exitCode, exitMessage, unknownException, logger);
            }

            return exitCode;
        }

        private void handleExitCode(int exitCode, String exitMessage, Exception e, LoggerWrapper logger)
                throws PluginExceptionHandler, ScannerException {
            if (exitCode != ErrorCode.BRIDGE_BUILD_BREAK && !Utility.isStringNullOrBlank(getMark_build_status())) {
                logger.info("Marking build status as " + getMark_build_status() + " is ignored since exit code is: "
                        + exitCode);
            }

            if (exitCode == ErrorCode.SCAN_SUCCESSFUL) {
                logger.println(
                        "**************************** END EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");
            } else {
                Result result = ParameterMappingService.getBuildResultIfIssuesAreFound(
                        exitCode, getMark_build_status(), logger);
                if (result != null) {
                    logger.info("Marking build as " + result + " since issues are present");
                    handleNonZeroExitCode(exitCode, result, exitMessage, e, logger);
                } else {
                    handleNonZeroExitCode(exitCode, Result.FAILURE, exitMessage, e, logger);
                }
            }
        }

        private void handleNonZeroExitCode(
                int exitCode, Result result, String exitMessage, Exception e, LoggerWrapper logger)
                throws PluginExceptionHandler, ScannerException {
            flowNode.addOrReplaceAction(new WarningAction(result)); // Setting the stage result
            run.setResult(result); // Setting the build result

            logger.println(
                    "**************************** END EXECUTION OF BLACK DUCK SECURITY SCAN ****************************");

            if (Objects.equals(isReturn_status(), true)) {
                return;
            }

            if (exitCode == ErrorCode.UNDEFINED_PLUGIN_ERROR) {
                // Throw exception with stack trace for undefined errors
                throw new ScannerException(exitMessage, e);
            } else {
                throw new PluginExceptionHandler(exitMessage);
            }
        }

        public void verifyRequiredPlugins(LoggerWrapper logger, EnvVars envVars) throws PluginExceptionHandler {
            String jobType = Utility.jenkinsJobType(envVars);
            SCMRepositoryService scmRepositoryService = new SCMRepositoryService(listener, envVars);
            Map<String, Boolean> installedBranchSourceDependencies = Utility.installedBranchSourceDependencies();

            if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
                if (installedBranchSourceDependencies.isEmpty()) {
                    logger.error(ApplicationConstants.NECESSARY_BRANCH_SOURCE_PLUGIN_IS_NOT_INSTALLED);
                    throw new PluginExceptionHandler(ErrorCode.REQUIRED_BRANCH_SOURCE_PLUGIN_NOT_INSTALLED);
                }
                SCMSource scmSource = scmRepositoryService.findSCMSource();
                if (!((installedBranchSourceDependencies.getOrDefault(
                                        ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, false)
                                && scmSource instanceof BitbucketSCMSource)
                        || (installedBranchSourceDependencies.getOrDefault(
                                        ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, false)
                                && scmSource instanceof GitHubSCMSource)
                        || (installedBranchSourceDependencies.getOrDefault(
                                        ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, false)
                                && scmSource instanceof GitLabSCMSource))) {
                    logger.error(ApplicationConstants.NECESSARY_BRANCH_SOURCE_PLUGIN_IS_NOT_INSTALLED);
                    throw new PluginExceptionHandler(ErrorCode.REQUIRED_BRANCH_SOURCE_PLUGIN_NOT_INSTALLED);
                }
            }
        }
    }
}
