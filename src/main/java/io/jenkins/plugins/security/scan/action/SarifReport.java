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

        public String getName() {
            return name;
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