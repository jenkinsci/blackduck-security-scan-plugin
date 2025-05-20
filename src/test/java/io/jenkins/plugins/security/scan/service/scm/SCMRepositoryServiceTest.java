package io.jenkins.plugins.security.scan.service.scm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.enums.InvokedFrom;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class SCMRepositoryServiceTest {

    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private SCMRepositoryService scmRepositoryService;

    @BeforeEach
    void setUp() throws Exception {
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        scmRepositoryService = new SCMRepositoryService(listenerMock, envVarsMock);
    }

    @Test
    void setRepositoryName_GitHubTest() {
        Github github = new Github();
        github.setRepository(new io.jenkins.plugins.security.scan.input.scm.github.Repository());
        github.getRepository().setName("github-repo");

        scmRepositoryService.setRepositoryName(github);

        assertEquals(RepositoryDetailsHolder.getRepositoryName(), "github-repo");
    }

    @Test
    void setRepositoryName_BitBucketTest() {
        Bitbucket bitbucket = Mockito.mock(Bitbucket.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Project project =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Project.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository repository =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository.class);

        Mockito.when(bitbucket.getProject()).thenReturn(project);
        Mockito.when(project.getRepository()).thenReturn(repository);
        Mockito.when(repository.getName()).thenReturn("bitbucket-repo");

        scmRepositoryService.setRepositoryName(bitbucket);

        assertEquals(RepositoryDetailsHolder.getRepositoryName(), "bitbucket-repo");
    }

    @Test
    void setRepositoryName_GitLabTest() {
        Gitlab gitlab = Mockito.mock(Gitlab.class);
        io.jenkins.plugins.security.scan.input.scm.gitlab.Repository repository =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.gitlab.Repository.class);

        Mockito.when(gitlab.getRepository()).thenReturn(repository);
        Mockito.when(repository.getName()).thenReturn("gitlab/repo/gitlab-repo");

        scmRepositoryService.setRepositoryName(gitlab);

        assertEquals(RepositoryDetailsHolder.getRepositoryName(), "gitlab-repo");
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_GitHubCloud() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://github.com/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new GitHubSCMSource("owner", "repo", "https://github.com/test/repo", true));

        assertEquals(InvokedFrom.INT_GITHUB_CLOUD, result);
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_GitHubEE() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://github-ee.com/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new GitHubSCMSource("owner", "repo", "https://github.com/test/repo", true));

        assertEquals(InvokedFrom.INT_GITHUB_EE, result);
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_BitbucketCloud() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://bitbucket.org/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new BitbucketSCMSource("owner", "repo"));

        assertEquals(InvokedFrom.INT_BITBUCKET_CLOUD, result);
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_BitbucketEE() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://bitbucket-ee.org/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new BitbucketSCMSource("owner", "repo"));

        assertEquals(InvokedFrom.INT_BITBUCKET_EE, result);
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_GitlabCloud() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://gitlab.com/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new GitLabSCMSource("gitlab.com", "owner", "repo/my-repo"));

        assertEquals(InvokedFrom.INT_GITLAB_CLOUD, result);
    }

    @Test
    void testGetInvokedFrom_MultiBranchJob_GitlabEE() {
        when(envVarsMock.get(ApplicationConstants.GIT_URL)).thenReturn("https://gitlab-ee.com/test/repo");

        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();
        installedBranchSourceDependencies.put(ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, true);

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies,
                ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME,
                new GitLabSCMSource("gitlab.com", "owner", "repo/my-repo"));

        assertEquals(InvokedFrom.INT_GITLAB_EE, result);
    }

    @Test
    void testGetInvokedFrom_FreestyleJob() {
        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();

        InvokedFrom result = scmRepositoryService.getInvokedFrom(
                installedBranchSourceDependencies, ApplicationConstants.FREESTYLE_JOB_TYPE_NAME, null);

        assertEquals(InvokedFrom.INT_JENKINS_FREESTYLE, result);
    }

    @Test
    void testGetInvokedFrom_PipelineJob() {
        Map<String, Boolean> installedBranchSourceDependencies = new HashMap<>();

        InvokedFrom result = scmRepositoryService.getInvokedFrom(installedBranchSourceDependencies, "pipeline", null);

        assertEquals(InvokedFrom.INT_JENKINS_PIPELINE, result);
    }
}
