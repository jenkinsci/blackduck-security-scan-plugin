package io.jenkins.plugins.security.scan.global.enums;

public enum TestScaType {
    SCA_PACKAGE("scaPackage"),
    SCA_SIGNATURE("scaSignature");

    private final String value;

    TestScaType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
