plugins {
    kotlin("jvm") version "1.9.21"
}

group = "de.arcan.arcshell"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
}

kotlin {
    jvmToolchain(17)
}
