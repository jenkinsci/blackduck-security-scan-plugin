package io.jenkins.plugins.security.scan.input.detect;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jenkins.plugins.security.scan.input.blackducksca.*;

public class Detect {
    @JsonProperty("install")
    private Install install;

    @JsonProperty("scan")
    private Scan scan;

    @JsonProperty("download")
    private Download download;

    @JsonProperty("search")
    private Search search;

    @JsonProperty("config")
    private Config config;

    @JsonProperty("args")
    private String args;

    @JsonProperty("execution")
    private Execution execution;

    public Install getInstall() {
        return install;
    }

    public void setInstall(Install install) {
        this.install = install;
    }

    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }

    public Download getDownload() {
        return download;
    }

    public void setDownload(final Download download) {
        this.download = download;
    }

    public Search getSearch() {
        return search;
    }

    public void setSearch(Search search) {
        this.search = search;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public String getArgs() {
        return args;
    }

    public void setArgs(String args) {
        this.args = args;
    }

    public Execution getExecution() {
        return execution;
    }

    public void setExecution(Execution execution) {
        this.execution = execution;
    }
}
