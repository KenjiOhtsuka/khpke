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
    version = "0.0.2"

    repositories {
        mavenCentral()
    }
}