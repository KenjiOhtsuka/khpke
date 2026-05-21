import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    `java-library`
}

apply(plugin = "org.jetbrains.kotlin.jvm")

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "11"
}