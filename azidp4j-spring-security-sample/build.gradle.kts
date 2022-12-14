import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    id("java")
    id("java-library")
    id("com.diffplug.spotless") version "6.10.0"
    id("org.springframework.boot") version "2.7.4"
    id("io.spring.dependency-management") version "1.0.14.RELEASE"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":azidp4j"))
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-web")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.8.1")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.13.3")
    testImplementation("org.jsoup:jsoup:1.15.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("net.sourceforge.htmlunit:htmlunit:2.36.0")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat("1.15.0").aosp().reflowLongStrings()
    }
}


//tasks.named<BootBuildImage>("bootBuildImage") {
//    docker {
//        host = "unix:///Users/juninaba/.docker/run/docker.sock"
//    }
//}
