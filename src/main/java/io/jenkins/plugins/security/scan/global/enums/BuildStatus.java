package io.jenkins.plugins.security.scan.global.enums;

import java.util.Arrays;

public enum BuildStatus {
    FAILURE,
    UNSTABLE,
    SUCCESS;

    public boolean in(BuildStatus... buildStatuses) {
        return Arrays.stream(buildStatuses).anyMatch(status -> status == this);
    }
}
