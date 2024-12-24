package io.jenkins.plugins.security.scan.input.blackducksca;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.security.scan.input.report.Reports;

public class BlackDuckSCA {
    @JsonProperty("url")
    private String url;

    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    @JsonProperty("token")
    private String token;

    @JsonProperty("scan")
    private Scan scan;

    @JsonProperty("automation")
    private Automation automation;

    @JsonProperty("fixPr")
    private FixPr fixPr;

    @JsonProperty("reports")
    private Reports reports;

    @JsonProperty("waitForScan")
    private Boolean waitForScan;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }

    public Automation getAutomation() {
        return automation;
    }

    public void setAutomation(Automation automation) {
        this.automation = automation;
    }

    public FixPr getFixPr() {
        return fixPr;
    }

    public void setFixPr(FixPr fixPr) {
        this.fixPr = fixPr;
    }

    public Reports getReports() {
        return reports;
    }

    public void setReports(Reports reports) {
        this.reports = reports;
    }

    public Boolean isWaitForScan() {
        return waitForScan;
    }

    public void setWaitForScan(Boolean waitForScan) {
        this.waitForScan = waitForScan;
    }
}
