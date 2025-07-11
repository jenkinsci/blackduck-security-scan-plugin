package io.jenkins.plugins.security.scan.input.network;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Network {
    @JsonProperty("airgap")
    private Boolean airgap;

    @JsonProperty("ssl")
    private SSL ssl;

    public Boolean getAirgap() {
        return airgap;
    }

    public void setAirgap(final Boolean airgap) {
        this.airgap = airgap;
    }

    public SSL getSsl() {
        return ssl;
    }

    public void setSsl(SSL ssl) {
        this.ssl = ssl;
    }
}
