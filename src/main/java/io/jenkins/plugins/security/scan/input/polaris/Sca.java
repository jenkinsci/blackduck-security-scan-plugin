package io.jenkins.plugins.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Sca {
    @JsonProperty("type")
    private String type;

    @JsonProperty("location")
    private String location;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }
}
