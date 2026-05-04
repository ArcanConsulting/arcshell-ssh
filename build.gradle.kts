plugins {
    kotlin("jvm") version "1.9.21"
}

group = "de.arcan.arcshell"
version = "2.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

kotlin {
    jvmToolchain(17)
}
