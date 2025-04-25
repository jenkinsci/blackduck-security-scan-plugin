package io.jenkins.plugins.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Sast {
    @JsonProperty("type")
    private List<String> type;

    public List<String> getType() {
        return type;
    }

    public void setType(List<String> type) {
        this.type = type;
    }
}
