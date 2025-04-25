package io.jenkins.plugins.security.scan.extension.pipeline;

public interface PrCommentScan {
    Boolean isBlackducksca_prComment_enabled();

    Boolean isBlackducksca_prComment_enabled_actualValue();

    @Deprecated
    Boolean isBlackduck_prComment_enabled();

    @Deprecated
    Boolean isBlackduck_prComment_enabled_actualValue();

    Boolean isCoverity_prComment_enabled();

    Boolean isCoverity_prComment_enabled_actualValue();

    Boolean isPolaris_prComment_enabled();

    Boolean isPolaris_prComment_enabled_actualValue();
}
