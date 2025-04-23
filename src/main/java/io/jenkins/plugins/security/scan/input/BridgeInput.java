package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.security.scan.input.blackducksca.BlackDuckSCA;
import io.jenkins.plugins.security.scan.input.coverity.Coverity;
import io.jenkins.plugins.security.scan.input.detect.Detect;
import io.jenkins.plugins.security.scan.input.polaris.Polaris;
import io.jenkins.plugins.security.scan.input.project.Project;
import io.jenkins.plugins.security.scan.input.report.Reports;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.security.scan.input.srm.SRM;

public class BridgeInput {
    @JsonProperty("blackducksca")
    private BlackDuckSCA blackDuckSCA;

    @JsonProperty("detect")
    private Detect detect;

    @JsonProperty("coverity")
    private Coverity coverity;

    @JsonProperty("polaris")
    private Polaris polaris;

    @JsonProperty("srm")
    private SRM srm;

    @JsonProperty("project")
    private Project project;

    @JsonProperty("bitbucket")
    private Bitbucket bitbucket;

    @JsonProperty("github")
    private Github github;

    @JsonProperty("gitlab")
    private Gitlab gitlab;

    @JsonProperty("network")
    private NetworkAirGap networkAirGap;

    @JsonProperty("reports")
    private Reports reports;

    @JsonProperty("bridge")
    private Bridge bridge;

    public Reports getReports() {
        return reports;
    }

    public void setReports(Reports reports) {
        this.reports = reports;
    }

    public BlackDuckSCA getBlackDuckSCA() {
        return blackDuckSCA;
    }

    public void setBlackDuckSCA(BlackDuckSCA blackDuckSCA) {
        this.blackDuckSCA = blackDuckSCA;
    }

    public Detect getDetect() {
        return detect;
    }

    public void setDetect(Detect detect) {
        this.detect = detect;
    }

    public Coverity getCoverity() {
        return coverity;
    }

    public void setCoverity(Coverity coverity) {
        this.coverity = coverity;
    }

    public Polaris getPolaris() {
        return polaris;
    }

    public void setPolaris(Polaris polaris) {
        this.polaris = polaris;
    }

    public SRM getSrm() {
        return srm;
    }

    public void setSrm(SRM srm) {
        this.srm = srm;
    }

    public Bitbucket getBitbucket() {
        return bitbucket;
    }

    public void setBitbucket(Bitbucket bitbucket) {
        this.bitbucket = bitbucket;
    }

    public NetworkAirGap getNetworkAirGap() {
        return networkAirGap;
    }

    public void setNetworkAirGap(final NetworkAirGap networkAirGap) {
        this.networkAirGap = networkAirGap;
    }

    public Github getGithub() {
        return github;
    }

    public void setGithub(Github github) {
        this.github = github;
    }

    public Gitlab getGitlab() {
        return gitlab;
    }

    public void setGitlab(Gitlab gitlab) {
        this.gitlab = gitlab;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Bridge getBridge() {
        return bridge;
    }

    public void setBridge(Bridge bridge) {
        this.bridge = bridge;
    }
}
