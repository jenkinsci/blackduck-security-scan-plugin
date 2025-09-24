package io.jenkins.plugins.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class PrComment {
    @JsonProperty("enabled")
    private Boolean enabled;

    @JsonProperty("impacts")
    private List<String> impacts;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getImpacts() {
        return impacts;
    }

    public void setImpacts(List<String> impacts) {
        this.impacts = impacts;
    }
}
