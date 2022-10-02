FROM openjdk:18-slim-buster
ARG JAR_FILE=build/libs/*.jar
RUN groupadd spring && useradd spring -g spring

USER spring:spring
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
