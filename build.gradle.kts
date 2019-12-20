import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "2.2.0.RELEASE"
    id("io.spring.dependency-management") version "1.0.8.RELEASE"
    kotlin("jvm") version "1.3.50"
    kotlin("plugin.spring") version "1.3.50"
    java
}

group = "com.example"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_1_8

val developmentOnly by configurations.creating
configurations {
    runtimeClasspath {
        extendsFrom(developmentOnly)
    }
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

repositories {
    mavenCentral()
    jcenter()
    maven { url = uri("https://repo.spring.io/milestone") }
    maven { url = uri("https://repository.jboss.org/nexus/content/repositories/thirdparty-releases/") }
}

extra["springCloudVersion"] = "Hoxton.RC1"

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.springframework.cloud:spring-cloud-gcp-starter")
    implementation("org.apache.pdfbox:pdfbox-app:2.0.17")
    implementation("org.apache.poi:poi:3.15")
    implementation("com.sun.media:jai-codec:1.1.3")
    implementation("javax.media:jai-core:1.1.3")
    implementation("org.apache.xmlgraphics:fop:2.4")
    implementation("org.apache.poi:poi-ooxml:3.15")
    implementation("org.apache.poi:poi-ooxml-schemas:3.15")
    implementation("fr.opensagres.xdocreport:org.apache.poi.xwpf.converter.pdf:1.0.6")
    implementation("org.bouncycastle:bcprov-jdk15on:1.61")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.61")
    implementation("com.google.apis:google-api-services-cloudkms:v1-rev89-1.25.0")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "1.8"
    }
}
