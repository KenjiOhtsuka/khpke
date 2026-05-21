plugins {
    java
}

import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

apply(plugin = "org.jetbrains.kotlin.jvm")

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    testImplementation(project(":hpke-core"))
    testImplementation(kotlin("test"))
    testImplementation("com.google.code.gson:gson:2.10.1")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "11"
}