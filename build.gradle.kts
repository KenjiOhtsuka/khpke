buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.24")
    }
}

allprojects {
    group = "io.github.kenjiohtsuka"
    version = "0.1.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}