package io.jenkins.plugins.security.scan.service.scm;

public class RepositoryDetailsHolder {
    private static String repositoryName;

    public static void setRepositoryName(String repositoryName) {
        RepositoryDetailsHolder.repositoryName = repositoryName;
    }

    public static String getRepositoryName() {
        return repositoryName;
    }
}
