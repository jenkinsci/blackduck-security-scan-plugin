package io.jenkins.plugins.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Automation {
    @JsonProperty("prComment")
    private Boolean prComment;

    public Boolean getPrComment() {
        return prComment;
    }

    public void setPrComment(Boolean prComment) {
        this.prComment = prComment;
    }
}
