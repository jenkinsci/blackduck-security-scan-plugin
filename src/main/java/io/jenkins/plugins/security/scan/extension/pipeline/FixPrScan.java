package io.jenkins.plugins.security.scan.extension.pipeline;

public interface FixPrScan {
    Boolean isBlackducksca_fixpr_enabled();

    Boolean isBlackducksca_fixpr_enabled_actualValue();

    String getBlackducksca_fixpr_filter_severities();

    String getBlackducksca_fixpr_useUpgradeGuidance();

    Integer getBlackducksca_fixpr_maxCount();

    Boolean isPolaris_fixpr_enabled();

    Boolean isPolaris_fixpr_enabled_actualValue();

    Integer getPolaris_fixpr_maxCount();

    String getPolaris_fixpr_useUpgradeGuidance();

    String getPolaris_fixpr_filter_severities();
}
