package io.jenkins.plugins.security.scan.global;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.junit.jupiter.api.Test;

public class IssueCalculatorTest {
    IssueCalculator issueCalculator = new IssueCalculator();

    @Test
    public void testGetIssuesUrl_Polaris() throws IOException {
        String jsonContent =
                "{" + "\"data\": {\"polaris\": {\"project\": {\"issues\": {\"url\": \"http://example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertEquals("http://example.com/issues", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_BlackDuckSca() throws IOException {
        String jsonContent = "{" + "\"data\": {\"blackducksca\": {\"projectBomUrl\": \"http://bd.example.com/bom\"}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "blackducksca";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertEquals("http://bd.example.com/bom", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_Coverity() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"coverity\": {\"connect\": {\"resultURL\": \"http://coverity.example.com/result\"}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "coverity";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertEquals("http://coverity.example.com/result", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_Srm() throws IOException {
        String jsonContent =
                "{" + "\"data\": {\"srm\": {\"project\": {\"issues\": {\"url\": \"http://srm.example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "srm";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertEquals("http://srm.example.com/issues", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_CaseInsensitive_BlackDuckSca() throws IOException {
        String jsonContent = "{" + "\"data\": {\"BLACKDUCKSCA\": {\"projectBomUrl\": \"http://bd.example.com/bom\"}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "blackducksca";
        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);
        assertEquals("http://bd.example.com/bom", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_CaseInsensitive_Coverity() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"COVERITY\": {\"CONNECT\": {\"resultURL\": \"http://coverity.example.com/result\"}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "coverity";
        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);
        assertEquals("http://coverity.example.com/result", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_CaseInsensitive_Polaris() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"POLARIS\": {\"project\": {\"issues\": {\"URL\": \"http://polaris.example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";
        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);
        assertEquals("http://polaris.example.com/issues", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_CaseInsensitive_Srm() throws IOException {
        String jsonContent =
                "{" + "\"data\": {\"SRM\": {\"project\": {\"issues\": {\"URL\": \"http://srm.example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "srm";
        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);
        assertEquals("http://srm.example.com/issues", issuesUrl);
    }

    @Test
    public void testGetIssuesUrl_InvalidProduct() throws IOException {
        // Arrange
        String jsonContent = "{"
                + "\"data\": {\"product1\": {\"project\": {\"issues\": {\"url\": \"http://example.com/issues\"}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "invalidProduct";

        String issuesUrl = issueCalculator.getIssuesUrl(rootNode, product);

        assertNull(issuesUrl);
    }

    @Test
    public void testCalculatePolarisIssues() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"polaris\": {\"test\": {\"SAST\": {\"tests\": {\"sastFull\": {\"issues\": {\"critical\": 2, \"high\": 3}}}}, \"SCA\": {\"tests\": {\"scaPackage\": {\"issues\": {\"medium\": 4, \"low\": 5}}}}}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";

        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);

        assertEquals(14, totalIssues);
    }

    @Test
    public void testCalculateSrmIssues() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"srm\": {\"analysis\": {\"issues\": {\"critical\": 10, \"high\": 5, \"medium\": 20, \"low\": 15}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "srm";

        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);

        assertEquals(50, totalIssues);
    }

    @Test
    public void testCalculateBlackduckIssues() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"blackducksca\": {\"policy\": {\"status\": {\"issues\": {\"critical\": 5, \"high\": 20, \"medium\": 10, \"low\": 15}}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "blackducksca";

        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);

        assertEquals(50, totalIssues);
    }

    @Test
    public void testCalculateCoverityIssues() throws IOException {
        String jsonContent = "{" + "\"data\": {\"coverity\": {\"connect\": {\"policy\": {\"issueCount\": 20}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "coverity";

        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);

        assertEquals(20, totalIssues);
    }

    @Test
    public void testCalculateIssues() throws IOException {
        String jsonContent = "{" + "\"issues\": {\"critical\": 2, \"high\": 3, \"medium\": 4, \"low\": 5}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode testNode = objectMapper.readTree(jsonContent);

        int totalIssues = issueCalculator.calculateIssues(testNode);

        assertEquals(14, totalIssues);
    }

    @Test
    public void testCalculateBlackDuckScaIssues_CaseInsensitive() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"BLACKDUCKSCA\": {\"policy\": {\"status\": {\"issues\": {\"CRITICAL\": 1, \"high\": 2}}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "blackducksca";
        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);
        assertEquals(3, totalIssues);
    }

    @Test
    public void testCalculateCoverityIssues_CaseInsensitive() throws IOException {
        String jsonContent = "{" + "\"data\": {\"COVERITY\": {\"CONNECT\": {\"policy\": {\"issueCount\": 7}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "coverity";
        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);
        assertEquals(7, totalIssues);
    }

    @Test
    public void testCalculatePolarisIssues_CaseInsensitive() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"POLARIS\": {\"test\": {\"SAST\": {\"TESTS\": {\"FULL\": {\"issues\": {\"CRITICAL\": 2, \"high\": 3}}}}, \"SCA\": {\"tests\": {\"SCAPACKAGE\": {\"IsSuEs\": {\"medium\": 4, \"LOW\": 5}}}}}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "polaris";
        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);
        assertEquals(14, totalIssues);
    }

    @Test
    public void testCalculateSrmIssues_CaseInsensitive() throws IOException {
        String jsonContent = "{"
                + "\"data\": {\"SRM\": {\"analysis\": {\"issues\": {\"CRITICAL\": 1, \"HIGH\": 2, \"medium\": 3, \"LOW\": 4}}}}}";
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(jsonContent);
        String product = "srm";
        int totalIssues = issueCalculator.calculateTotalIssues(rootNode, product);
        assertEquals(10, totalIssues);
    }
}
