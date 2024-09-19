package io.jenkins.plugins.security.scan.service.scm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RepositoryDetailsHolderTest {
    @BeforeEach
    public void resetRepositoryName() {
        RepositoryDetailsHolder.setRepositoryName(null);
    }

    @Test
    public void testSetAndGetRepositoryName() {
        String repositoryName = "test-repo";
        RepositoryDetailsHolder.setRepositoryName(repositoryName);

        assertEquals(
                repositoryName,
                RepositoryDetailsHolder.getRepositoryName(),
                "Repository name should match the set value.");
    }

    @Test
    public void testRepositoryNameInitiallyNull() {
        assertNull(RepositoryDetailsHolder.getRepositoryName(), "Repository name should be null initially.");
    }

    @Test
    public void testRepositoryNameOverwrite() {
        RepositoryDetailsHolder.setRepositoryName("initial-repo");
        RepositoryDetailsHolder.setRepositoryName("new-repo");

        assertEquals(
                "new-repo",
                RepositoryDetailsHolder.getRepositoryName(),
                "Repository name should be overwritten with the new value.");
    }
}
