package io.jenkins.plugins.security.scan.input.blackduck;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Automation {
    @JsonProperty("fixpr")
    private Boolean fixpr;

    @JsonProperty("prComment")
    private Boolean prComment;

    public Boolean getFixpr() {
        return fixpr;
    }

    public void setFixpr(Boolean fixpr) {
        this.fixpr = fixpr;
    }

    public Boolean getPrComment() {
        return prComment;
    }

    public void setPrComment(Boolean prComment) {
        this.prComment = prComment;
    }
}
