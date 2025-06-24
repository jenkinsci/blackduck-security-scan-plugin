package io.jenkins.plugins.security.scan.global.enums;

public enum InvokedFrom {
    INT_JENKINS_FREESTYLE("Integrations-jenkins-freestyle"),
    INT_JENKINS_PIPELINE("Integrations-jenkins-pipeline"),
    INT_GITHUB_CLOUD("Integrations-jenkins-github-cloud"),
    INT_GITHUB_EE("Integrations-jenkins-github-ee"),
    INT_BITBUCKET_CLOUD("Integrations-jenkins-bitbucket-cloud"),
    INT_BITBUCKET_EE("Integrations-jenkins-bitbucket-ee"),
    INT_GITLAB_CLOUD("Integrations-jenkins-gitlab-cloud"),
    INT_GITLAB_EE("Integrations-jenkins-gitlab-ee");

    private final String value;

    InvokedFrom(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
