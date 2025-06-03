package io.jenkins.plugins.security.scan.global.enums;

public enum InvokedFrom {
    INT_JENKINS_FREESTYLE("Integrations-jenkins-freestyle"),
    INT_JENKINS_PIPELINE("Integrations-jenkins-pipeline"),
    INT_GITHUB_CLOUD("Integrations-github-cloud"),
    INT_GITHUB_EE("Integrations-github-ee"),
    INT_BITBUCKET_CLOUD("Integrations-bitbucket-cloud"),
    INT_BITBUCKET_EE("Integrations-bitbucket-ee"),
    INT_GITLAB_CLOUD("Integrations-gitlab-cloud"),
    INT_GITLAB_EE("Integrations-gitlab-ee");

    private final String value;

    InvokedFrom(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
