// The Connectivitizer SDK for the JVM: Kotlin, usable from Java, and the same jar runs on Android (API 28+).
plugins {
    kotlin("jvm") version "2.2.20"
    `java-library`
    `maven-publish`
}

group = "com.huelake"
// The release pipeline sets the version (build/sdk/pack.sh: -PpackageVersion=...); local builds stay 1.0.0-dev.
version = providers.gradleProperty("packageVersion").getOrElse("1.0.0-dev")

repositories {
    mavenCentral()
}

dependencies {
    // The only dependency. Everything else (WebSocket, HTTP, UDP, KCP, X25519, the Noise handshake) is in this library and the JDK.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        // Bytecode for Java 11, which Android's desugaring and every current JVM accept.
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        freeCompilerArgs.add("-Xjdk-release=11")
    }
}

java {
    withSourcesJar()
    targetCompatibility = JavaVersion.VERSION_11
}

// Java sources (only the tests that call the SDK the way a Java program does) compile for the same Java 11.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
}

tasks.test {
    useJUnitPlatform()
    systemProperty("connectivitizer.vectors", rootDir.resolve("../../docs/protocol/vectors").canonicalPath)
}

// Maven Central requires a javadoc jar. The API is documented in the KDoc comments and on connectivitizer.com; the jar
// carries the README.
val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(rootDir.resolve("README.md"))
}

// The license travels in every jar.
tasks.withType<Jar>().configureEach {
    from(rootDir.resolve("LICENSE")) { into("META-INF") }
}

publishing {
    publications {
        create<MavenPublication>("library") {
            artifactId = "connectivitizer"
            from(components["java"])
            artifact(javadocJar)
            // What Maven Central requires of every POM.
            pom {
                name.set("Connectivitizer")
                description.set("Connectivitizer SDK for the JVM and Android: reach services on devices behind NAT, end-to-end encrypted, relayed or peer to peer; and run a device.")
                url.set("https://connectivitizer.com")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/license/mit")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("huelake")
                        name.set("Huelake")
                        email.set("info@huelake.com")
                        organization.set("Huelake Software Solutions UG (haftungsbeschränkt)")
                        organizationUrl.set("https://huelake.com")
                    }
                }
                scm {
                    url.set("https://github.com/huelake/connectivitizer-sdk")
                    connection.set("scm:git:https://github.com/huelake/connectivitizer-sdk.git")
                    developerConnection.set("scm:git:ssh://git@github.com/huelake/connectivitizer-sdk.git")
                }
            }
        }
    }
    repositories {
        // A local Maven repository, for development builds.
        maven {
            name = "artifacts"
            url = uri(rootDir.resolve("../../artifacts/packages/maven"))
        }
        // The bundle for Maven Central, before it is signed.
        maven {
            name = "staging"
            url = uri(layout.buildDirectory.dir("staging-repo"))
        }
    }
}

// The interoperability programs (src/test/kotlin/.../interop) run as separate processes; the tests that start
// them read their classpath from this file.
tasks.register("interopClasspath") {
    dependsOn("testClasses")
    val output = layout.buildDirectory.file("interop-classpath.txt")
    outputs.file(output)
    doLast {
        val classpath = sourceSets["test"].runtimeClasspath.files.joinToString(File.pathSeparator) { it.absolutePath }
        output.get().asFile.writeText(classpath)
    }
}
