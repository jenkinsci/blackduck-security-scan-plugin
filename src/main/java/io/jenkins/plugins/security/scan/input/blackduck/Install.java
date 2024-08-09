package io.jenkins.plugins.security.scan.input.blackduck;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Install {
    @JsonProperty("directory")
    private String directory;

    public String getDirectory() {
        return directory;
    }

    public void setDirectory(String directory) {
        this.directory = directory;
    }
}
