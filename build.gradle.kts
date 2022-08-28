plugins {
    id("java")
    id("com.diffplug.spotless") version "6.10.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")

    implementation("com.nimbusds:nimbus-jose-jwt:9.24.3")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat("1.8").aosp().reflowLongStrings()
    }
}