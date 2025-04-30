package io.jenkins.plugins.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Test {
    @JsonProperty("sca")
    private Sca sca;

    private Sast sast;

    public Sca getSca() {
        return sca;
    }

    public void setSca(Sca sca) {
        this.sca = sca;
    }

    public Sast getSast() {
        return sast;
    }

    public void setSast(Sast sast) {
        this.sast = sast;
    }
}
