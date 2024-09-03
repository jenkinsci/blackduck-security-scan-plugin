package io.jenkins.plugins.security.scan.input.detect;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Search {
    @JsonProperty("depth")
    private Integer depth;

    public Integer getDepth() {
        return depth;
    }

    public void setDepth(Integer depth) {
        this.depth = depth;
    }
}
