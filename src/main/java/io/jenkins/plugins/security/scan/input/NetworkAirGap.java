package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NetworkAirGap {
    @JsonProperty("airgap")
    private Boolean airgap;

    public Boolean getAirgap() {
        return airgap;
    }

    public void setAirgap(final Boolean airgap) {
        this.airgap = airgap;
    }
}
