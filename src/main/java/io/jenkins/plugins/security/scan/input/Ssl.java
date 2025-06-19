package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Ssl {
    @JsonProperty("trust")
    private SslTrust trust;

    @JsonProperty("cert")
    private SslCert cert;

    public SslTrust getTrust() {
        return trust;
    }

    public void setTrust(SslTrust trust) {
        this.trust = trust;
    }

    public SslCert getCert() {
        return cert;
    }

    public void setCert(SslCert cert) {
        this.cert = cert;
    }
}