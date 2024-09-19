package io.jenkins.plugins.security.scan.input.coverity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Connect {
    @JsonProperty("url")
    private String url;

    @JsonProperty("user")
    private User user;

    @JsonProperty("project")
    private CoverityProject coverityProject;

    @JsonProperty("stream")
    private Stream stream;

    @JsonProperty("policy")
    private Policy policy;

    public Connect() {
        user = new User();
        coverityProject = new CoverityProject();
        stream = new Stream();
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public CoverityProject getCoverityProject() {
        return coverityProject;
    }

    public void setCoverityProject(CoverityProject coverityProject) {
        this.coverityProject = coverityProject;
    }

    public Stream getStream() {
        return stream;
    }

    public void setStream(Stream stream) {
        this.stream = stream;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }
}
