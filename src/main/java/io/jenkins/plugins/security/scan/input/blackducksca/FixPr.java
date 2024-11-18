package io.jenkins.plugins.security.scan.input.blackducksca;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FixPr {
    @JsonProperty("enabled")
    private Boolean enabled;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }
}
