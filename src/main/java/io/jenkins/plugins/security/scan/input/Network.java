package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Network {
    @JsonProperty("airgap")
    private Boolean airgap;

    @JsonProperty("ssl")
    private Ssl ssl;

    public Boolean getAirgap() {
        return airgap;
    }

    public void setAirgap(final Boolean airgap) {
        this.airgap = airgap;
    }

    public Ssl getSsl() {
        return ssl;
    }

    public void setSsl(Ssl ssl) {
        this.ssl = ssl;
    }
}