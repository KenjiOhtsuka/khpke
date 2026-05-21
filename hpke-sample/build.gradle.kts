import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    application
}

apply(plugin = "org.jetbrains.kotlin.jvm")

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

application {
    mainClass.set("io.github.kenjiohtsuka.khpke.sample.BasicExampleKt")
}

dependencies {
    implementation(project(":hpke-core"))
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "11"
}