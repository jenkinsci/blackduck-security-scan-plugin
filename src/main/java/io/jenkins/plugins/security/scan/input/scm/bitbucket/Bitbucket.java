package io.jenkins.plugins.security.scan.input.scm.bitbucket;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Bitbucket {
    @JsonProperty("api")
    private Api api;

    @JsonProperty("project")
    private Project project;

    @JsonProperty("workspace")
    private Workspace workspace;

    public Bitbucket() {
        api = new Api();
        project = new Project();
    }

    public Api getApi() {
        return api;
    }

    public void setApi(Api api) {
        this.api = api;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Workspace getWorkspace() {
        return workspace;
    }

    public void setWorkspace(Workspace workspace) {
        this.workspace = workspace;
    }
}
