package io.jenkins.plugins.security.scan.action;

import static org.junit.jupiter.api.Assertions.*;

import hudson.FilePath;
import java.io.File;
import org.junit.jupiter.api.Test;

public class IssueActionItemsTest {
    FilePath filePath = new FilePath(new File("dummyPath"));

    @Test
    public void testGetProduct() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertEquals("blackducksca", actionItems.getProduct());
    }

    @Test
    public void testGetFilePath() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertEquals(filePath, actionItems.getFilePath());
    }

    @Test
    public void testGetProductUrl() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertEquals("http://example.com", actionItems.getProductUrl());
    }

    @Test
    public void testIsPrEvent() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertTrue(actionItems.isPrEvent());
    }

    @Test
    public void testGetIconFileName() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertNull(actionItems.getIconFileName());
    }

    @Test
    public void testGetDisplayName() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertNull(actionItems.getDisplayName());
    }

    @Test
    public void testGetUrlName() {
        IssueActionItems actionItems = new IssueActionItems("blackducksca", "http://example.com", filePath, true);
        assertNull(actionItems.getUrlName());
    }
}
