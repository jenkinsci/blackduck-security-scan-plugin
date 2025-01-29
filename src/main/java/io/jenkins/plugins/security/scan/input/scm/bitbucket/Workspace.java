package io.jenkins.plugins.security.scan.input.scm.bitbucket;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Workspace {
    @JsonProperty("id")
    private String id;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
