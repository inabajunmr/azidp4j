plugins {
    id("java")
    id("java-library")
    id("com.diffplug.spotless") version "6.10.0"
    id("maven-publish")
    id("signing")
}

group = "io.github.inabajunmr"
version = "0.0.0-alpha+001"

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

// https://docs.gradle.org/current/userguide/publishing_maven.html
java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "AzIdP4J"
            from(components["java"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
            pom {
                name.set("AzIdP4J")
                description.set("AzIdP4J is library for Java OAuth 2.0 Authorization Server & OpenID Connect Identity Provider")
                url.set("https://github.com/inabajunmr/azidp4j")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://github.com/inabajunmr/azidp4j/blob/main/LICENSE")
                    }
                }
                developers {
                    developer {
                        id.set("inabajunmr")
                        name.set("inaba jun")
                        email.set("inabajun.for.regi@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://inabajunmr/azidp4j.git")
                    developerConnection.set("scm:git:ssh://inabajunmr/azidp4j.git")
                    url.set("https://github.com/inabajunmr/azidp4j")
                }
            }
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsRepoUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/");
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
            credentials {
                if(project.hasProperty("sonatypeUsername")) {
                    username = project.property("sonatypeUsername").toString()
                }
                if(project.hasProperty("sonatypePassword")) {
                    password = project.property("sonatypePassword").toString()
                }
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}
