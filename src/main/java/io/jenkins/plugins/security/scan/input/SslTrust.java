package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SslTrust {
    @JsonProperty("all")
    private Boolean all;

    public Boolean getAll() {
        return all;
    }

    public void setAll(Boolean all) {
        this.all = all;
    }
}