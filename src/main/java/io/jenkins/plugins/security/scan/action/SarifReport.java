package io.jenkins.plugins.security.scan.action;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SarifReport {
    @JsonProperty("runs")
    private List<Run> runs;

    public List<Run> getRuns() {
        return runs;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Run {
        @JsonProperty("results")
        private List<Result> results;

        @JsonProperty("tool")
        private Tool tool;

        public List<Result> getResults() {
            return results;
        }

        public Tool getTool() {
            return tool;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Tool {
        @JsonProperty("driver")
        private Driver driver;

        public Driver getDriver() {
            return driver;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Driver {
        @JsonProperty("name")
        private String name;

        @JsonProperty("rules")
        private List<Rule> rules;

        public String getName() {
            return name;
        }

        public List<Rule> getRules() {
            return rules;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Rule {
        @JsonProperty("id")
        private String id;

        @JsonProperty("properties")
        private Properties properties;

        @JsonProperty("help")
        private Help help;

        @JsonProperty("shortDescription")
        private ShortDescription shortDescription;

        public String getId() {
            return id;
        }

        public Properties getProperties() {
            return properties;
        }

        public Help getHelp() {
            return help;
        }

        public ShortDescription getShortDescription() {
            return shortDescription;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ShortDescription {
        @JsonProperty("text")
        private String text;

        public String getText() {
            return text;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Properties {
        @JsonProperty("security-severity")
        private String securitySeverity;

        public String getSecuritySeverity() {
            return securitySeverity;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Help {
        @JsonProperty("text")
        private String text;

        @JsonProperty("markdown")
        private String markdown;

        public String getText() {
            return text;
        }

        public String getMarkdown() {
            return markdown;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Result {
        @JsonProperty("ruleId")
        private String ruleId;

        @JsonProperty("message")
        private Message message;

        @JsonProperty("locations")
        private List<Location> locations;

        @JsonProperty("level")
        private String level;

        public String getRuleId() {
            return ruleId;
        }

        public Message getMessage() {
            return message;
        }

        public List<Location> getLocations() {
            return locations;
        }

        public String getLevel() {
            return level;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Message {
        @JsonProperty("text")
        private String text;

        public String getText() {
            return text;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Location {
        @JsonProperty("physicalLocation")
        private PhysicalLocation physicalLocation;

        public PhysicalLocation getPhysicalLocation() {
            return physicalLocation;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PhysicalLocation {
        @JsonProperty("artifactLocation")
        private ArtifactLocation artifactLocation;

        @JsonProperty("region")
        private Region region;

        public ArtifactLocation getArtifactLocation() {
            return artifactLocation;
        }

        public Region getRegion() {
            return region;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ArtifactLocation {
        @JsonProperty("uri")
        private String uri;

        public String getUri() {
            return uri;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Region {
        @JsonProperty("startLine")
        private int startLine;

        public int getStartLine() {
            return startLine;
        }
    }
}
