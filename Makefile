clean:
	echo "Provide the Clean command like mvn clean/rm -rf /repo/target/*"
	./mvnw clean

compile:
	echo "Provide the Compile command like mvn compile"
	./mvnw compile

prerequisites:
	echo "Prequisites: Java 17, Maven 3.9.6, Docker, and Git installed and configured properly."

build: prerequisites
	./mvnw clean install -DskipTests

dependencies: prerequisites
	echo "Provide the Dependency command or env variables"
	echo "export MAVEN_EXEC=./mvnw"
	echo "export MAVEN_COMMAND=\"-Dmaven.test.skip -DskipTests -Ddockerfile.skip -Denforcer.skip -Dmdep.analyze.skip --batch-mode --also-make compile\"" >> /tmp/.env

image_scan:
	echo "Provide the commands for BD Docker Image Scan"

.PHONY: clean