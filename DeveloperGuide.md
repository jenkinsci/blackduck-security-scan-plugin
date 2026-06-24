## Developers Guide

To work with the project locally and run it with a Jenkins server, follow these steps:

1. Run Jenkins server locally with the plugin being deployed:
```
./mvnw hpi:run
```
> Enter https://localhost:8080/jenkins in your browser

**Note:** Make sure that **port 8080** is free on your machine, and you have
**_Pipeline_** plugin installed in your Jenkins server to configure the multibranch pipeline job.

2. Build the project:
```
./mvnw clean install
```

3. Generate the `hpi` file:
```
./mvnw hpi:hpi
```

The generated `hpi` file can be found in the `target` folder of your project directory.