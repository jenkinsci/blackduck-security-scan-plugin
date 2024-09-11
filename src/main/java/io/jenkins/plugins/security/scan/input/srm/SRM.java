package io.jenkins.plugins.security.scan.input.srm;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SRM {
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("url")
    private String url;

    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("apikey")
    private String apikey;

    @JsonProperty("assessment")
    private AssessmentTypes assessmentTypes;

    @JsonProperty("project")
    private SrmProject srmProject;

    @JsonProperty("branch")
    private Branch branch;

    @JsonProperty("waitForScan")
    private Boolean waitForScan;

    public SRM() {
        assessmentTypes = new AssessmentTypes();
        srmProject = new SrmProject();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getApikey() {
        return apikey;
    }

    public void setApikey(String apikey) {
        this.apikey = apikey;
    }

    public AssessmentTypes getAssessmentTypes() {
        return assessmentTypes;
    }

    public void setAssessmentTypes(AssessmentTypes assessmentTypes) {
        this.assessmentTypes = assessmentTypes;
    }

    public SrmProject getSrmProject() {
        return srmProject;
    }

    public void setSrmProject(SrmProject srmProject) {
        this.srmProject = srmProject;
    }

    public Branch getBranch() {
        return branch;
    }

    public void setBranch(Branch branch) {
        this.branch = branch;
    }

    public Boolean isWaitForScan() {
        return waitForScan;
    }

    public void setWaitForScan(Boolean waitForScan) {
        this.waitForScan = waitForScan;
    }
}
