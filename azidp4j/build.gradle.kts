plugins {
    id("java")
    id("java-library")
    id("com.diffplug.spotless") version "6.10.0"
    id("maven-publish")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.8.1")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")

    api("com.nimbusds:nimbus-jose-jwt:9.24.3")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat("1.15.0").aosp().reflowLongStrings()
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "org.azidp4j"
            artifactId = "library"
            version = "1.1"

            from(components["java"])
        }
    }
}