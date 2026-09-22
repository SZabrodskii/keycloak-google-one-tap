import com.diffplug.spotless.LineEnding

plugins {
    java
    alias(libs.plugins.spotless)
    alias(libs.plugins.shadow)
}

repositories {
    mavenCentral()
    google()
}

group = "dev.avatsav"
version = libs.versions.keycloak.get()

dependencies {
    compileOnly(libs.keycloak.core)
    compileOnly(libs.keycloak.services)
    compileOnly(libs.keycloak.serverSpi)
    compileOnly(libs.keycloak.serverSpi.private)
    // Only the java.net transport is used; keep Apache HttpClient out of the shadow jar so it
    // cannot shadow the copy Keycloak ships for its own HttpClientProvider.
    implementation(libs.google.apiClient) {
        exclude(group = "com.google.http-client", module = "google-http-client-apache-v2")
        exclude(group = "org.apache.httpcomponents")
    }

    testImplementation(libs.keycloak.core)
    testImplementation(libs.keycloak.services)
    testImplementation(libs.keycloak.serverSpi)
    testImplementation(libs.keycloak.serverSpi.private)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockito.core)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.resteasy.core)
}

java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }

spotless {
    java {
        googleJavaFormat()
        removeUnusedImports()
    }
    lineEndings = LineEnding.PLATFORM_NATIVE
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
}

tasks.test { useJUnitPlatform() }
