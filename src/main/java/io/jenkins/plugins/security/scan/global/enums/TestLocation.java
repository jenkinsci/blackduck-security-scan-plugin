package io.jenkins.plugins.security.scan.global.enums;

public enum TestLocation {
	LOCAL("LOCAL", "local"),
	HYBRID("HYBRID", "hybrid"),
	REMOTE("REMOTE", "remote");

	private final String name;
	private final String value;

	TestLocation(String name, String value) {
		this.name = name;
		this.value = value;
	}

	public String getName() {
		return name;
	}

	public String getValue() {
		return value;
	}
}
