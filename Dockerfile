# ============================================================================
# Stage 1: Build JAR using Maven
# ============================================================================
FROM maven:3.9.6-eclipse-temurin-17-alpine AS builder
WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests

# ============================================================================
# Stage 2: Minimal JRE Runtime
# ============================================================================
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Create storage directory for evidence artifacts
RUN mkdir -p vault_storage

# Copy fat JAR from build stage
COPY --from=builder /app/target/ProofVault-1.0.0.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
