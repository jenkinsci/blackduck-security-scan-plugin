package io.jenkins.plugins.security.scan.service.scm;

import static org.junit.jupiter.api.Assertions.assertEquals;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import java.io.PrintStream;
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
}
