package io.jenkins.plugins.security.scan.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import org.junit.jupiter.api.Test;

public class IssueActionTest {

    @Test
    public void testGetIconFileName() {
        IssueAction action = new IssueAction("blackducksca", 10, "http://example.com");
        assertEquals(ApplicationConstants.BLACK_DUCK_LOGO_FILE_NAME, action.getIconFileName());
    }

    @Test
    public void testGetDisplayName() {
        IssueAction action = new IssueAction("blackducksca", 10, "http://example.com");
        assertEquals("See 10 issues in Black Duck SCA", action.getDisplayName());
    }

    @Test
    public void testGetUrlName() {
        IssueAction action = new IssueAction("blackducksca", 10, "http://example.com");
        assertEquals("http://example.com", action.getUrlName());
    }
}
