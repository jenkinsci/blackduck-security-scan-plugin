package io.jenkins.plugins.security.scan.input;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SslCert {
    @JsonProperty("file")
    private String file;

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }
}