package io.jenkins.plugins.security.scan.input.detect;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Config {
    @JsonProperty("path")
    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }
}
