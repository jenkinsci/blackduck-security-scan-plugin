package io.jenkins.plugins.security.scan.input.network;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SSL {
    @JsonProperty("trustAll")
    private Boolean trustAll;

    @JsonProperty("cert")
    private Cert cert;


    public Boolean getTrustAll() {
        return trustAll;
    }

    public void setTrustAll(Boolean trustAll) {
        this.trustAll = trustAll;
    }

    public Cert getCert() {
        return cert;
    }

    public void setCert(Cert cert) {
        this.cert = cert;
    }
}
