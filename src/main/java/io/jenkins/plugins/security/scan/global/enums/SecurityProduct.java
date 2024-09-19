package io.jenkins.plugins.security.scan.global.enums;

public enum SecurityProduct {
    BLACKDUCK("Blackduck"),
    BLACKDUCKSCA("Black Duck SCA"),
    COVERITY("Coverity"),
    POLARIS("Polaris"),
    SRM("Software Risk Manager (SRM)");

    private final String productLabel;

    SecurityProduct(String productLabel) {
        this.productLabel = productLabel;
    }

    public String getProductLabel() {
        return productLabel;
    }
}
