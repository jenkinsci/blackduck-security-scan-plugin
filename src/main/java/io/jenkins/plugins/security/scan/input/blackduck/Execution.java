package io.jenkins.plugins.security.scan.input.blackduck;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Execution {
    @JsonProperty("path")
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
}