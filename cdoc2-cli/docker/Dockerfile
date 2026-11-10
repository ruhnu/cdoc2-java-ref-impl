# ruhnu-cli: cdoc2-cli for encrypting to SSH public keys and decrypting through ssh-agent.
# Build context is a directory holding this Dockerfile and the shaded jar named cdoc2-cli.jar,
# see "Docker image" in ../README.md.
FROM bellsoft/liberica-runtime-container:jre-21-slim-musl
COPY cdoc2-cli.jar /opt/cdoc2/cdoc2-cli.jar
ENV LANG=C.UTF-8
WORKDIR /work
ENTRYPOINT ["java", "-jar", "/opt/cdoc2/cdoc2-cli.jar"]
