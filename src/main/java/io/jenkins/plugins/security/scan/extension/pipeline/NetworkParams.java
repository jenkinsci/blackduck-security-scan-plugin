package io.jenkins.plugins.security.scan.extension.pipeline;

public interface NetworkParams {
    public Boolean isNetwork_airgap();

    public String getNetwork_ssl_cert_file();

    public Boolean isNetwork_ssl_trustAll();
}
