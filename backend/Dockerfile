# syntax=docker/dockerfile:1

# Stage 1: Build Application Artifact
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /workspace

COPY .mvn .mvn
COPY mvnw mvnw
COPY pom.xml pom.xml
COPY lombok.config lombok.config
COPY src src

RUN chmod +x mvnw && ./mvnw package -DskipTests -B

# Stage 2: Hardened Non-Root Minimal Runtime
FROM eclipse-temurin:21-jre-alpine AS runtime

RUN addgroup -g 10001 ospysin && adduser -D -u 10001 -G ospysin ospysin

WORKDIR /app

COPY --from=builder /workspace/target/*.jar /app/app.jar
RUN chown -R 10001:10001 /app

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
