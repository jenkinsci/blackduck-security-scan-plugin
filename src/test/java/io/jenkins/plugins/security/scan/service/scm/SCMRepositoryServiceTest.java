package io.jenkins.plugins.security.scan.service.scm;

import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.PrintStream;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SCMRepositoryServiceTest {

    private final TaskListener listenerMock = Mockito.mock(TaskListener.class);
    private final EnvVars envVarsMock = Mockito.mock(EnvVars.class);
    private SCMRepositoryService scmRepositoryService;

    @BeforeEach
    void setUp() throws Exception {
        Mockito.when(listenerMock.getLogger()).thenReturn(Mockito.mock(PrintStream.class));
        scmRepositoryService = new SCMRepositoryService(listenerMock, envVarsMock);
        setRepositoryNameField(null);
    }

    @Test
    void setRepositoryName_GitHubTest() throws Exception {
        Github github = new Github();
        github.setRepository(new io.jenkins.plugins.security.scan.input.scm.github.Repository());
        github.getRepository().setName("github-repo");

        scmRepositoryService.setRepositoryName(github);

        assertEquals(getRepositoryNameField(), "github-repo");
    }

    @Test
    void setRepositoryName_BitBucketTest() throws Exception {
        Bitbucket bitbucket = Mockito.mock(Bitbucket.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Project project =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Project.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository repository =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository.class);

        Mockito.when(bitbucket.getProject()).thenReturn(project);
        Mockito.when(project.getRepository()).thenReturn(repository);
        Mockito.when(repository.getName()).thenReturn("bitbucket-repo");

        scmRepositoryService.setRepositoryName(bitbucket);

        assertEquals(getRepositoryNameField(), "bitbucket-repo");
    }

    @Test
    void setRepositoryName_GitLabTest() throws Exception {
        Gitlab gitlab = Mockito.mock(Gitlab.class);
        io.jenkins.plugins.security.scan.input.scm.gitlab.Repository repository =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.gitlab.Repository.class);

        Mockito.when(gitlab.getRepository()).thenReturn(repository);
        Mockito.when(repository.getName()).thenReturn("gitlab/repo/gitlab-repo");

        scmRepositoryService.setRepositoryName(gitlab);

        assertEquals(getRepositoryNameField(), "gitlab-repo");
    }

    @Test
    void getRepositoryNameTest() throws Exception {
        Bitbucket bitbucket = Mockito.mock(Bitbucket.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Project project =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Project.class);
        io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository repository =
                Mockito.mock(io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository.class);

        Mockito.when(bitbucket.getProject()).thenReturn(project);
        Mockito.when(project.getRepository()).thenReturn(repository);
        Mockito.when(repository.getName()).thenReturn("bitbucket-repo");

        scmRepositoryService.setRepositoryName(bitbucket);

        assertEquals(SCMRepositoryService.getRepositoryName(), "bitbucket-repo");
    }

    // Helper method to access the private static field using reflection
    private String getRepositoryNameField() throws Exception {
        Field field = SCMRepositoryService.class.getDeclaredField("repositoryName");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    // Helper method to set the private static field using reflection
    private void setRepositoryNameField(String value) throws Exception {
        Field field = SCMRepositoryService.class.getDeclaredField("repositoryName");
        field.setAccessible(true);
        field.set(null, value);
    }

}
