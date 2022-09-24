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
    implementation(project(":azidp4j"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.8.1")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat("1.15.0").aosp().reflowLongStrings()
    }
}