package io.jenkins.plugins.security.scan.extension.freestyle;

public interface FreestyleScan {
    Integer getPolaris_sca_search_depth();

    String getPolaris_sca_config_path();

    String getPolaris_sca_args();

    String getPolaris_sast_build_command();

    String getPolaris_sast_clean_command();

    String getPolaris_sast_config_path();

    String getPolaris_sast_args();

    Integer getSrm_sca_search_depth();

    String getSrm_sca_config_path();

    String getSrm_sca_args();

    String getSrm_sast_build_command();

    String getSrm_sast_clean_command();

    String getSrm_sast_config_path();

    String getSrm_sast_args();
}
