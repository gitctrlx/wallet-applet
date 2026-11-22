import org.gradle.process.CommandLineArgumentProvider

plugins {
    `java-library`
}

val apiClassicJar =
    rootProject.layout.projectDirectory.file(
        "sdks/${libs.versions.javacard.sdk.get()}/lib/api_classic-${libs.versions.javacard.target.get()}.jar"
    )

java {
    sourceSets {
        named("main") {
            // Vendored jcardsim fork and the org.qntx.card.sim runtime compile
            // as one source set: the fork patches call into our hooks.
            java.srcDir("jcardsim/src/main/java")
        }
    }
}

dependencies {
    compileOnly(files(apiClassicJar.asFile))
    api(libs.bouncycastle.prov)
    implementation(libs.asm.commons)
    implementation(libs.asm.tree)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.compileJava {
    options.release = 25
}

// jcardsim merges the *Proxy classes into the Java Card API classes after
// compilation (upstream does this in an ant step). The merged javacard.* /
// javacardx.* classes land in build/jcapi and ride the main source-set
// output, so api_classic itself never reaches a runtime classpath.
val jcapiDir = layout.buildDirectory.dir("jcapi")
val javacardApiStaging = layout.buildDirectory.dir("javacardApiStaging")

val compiledClasses = tasks.compileJava.flatMap { it.destinationDirectory }

val stageJavacardApi =
    tasks.register<Copy>("stageJavacardApi") {
        from(compiledClasses)
        from(zipTree(apiClassicJar.asFile)) {
            exclude("java/**")
        }
        into(javacardApiStaging)
    }

val processJavacardApi =
    tasks.register<JavaExec>("processJavacardApi") {
        dependsOn(stageJavacardApi)
        // api_classic sits on this JVM's classpath only so ASM's
        // COMPUTE_FRAMES can resolve javacard.* supertypes; it is never
        // on a consumer classpath.
        classpath = files(compiledClasses, apiClassicJar, configurations.runtimeClasspath)
        mainClass.set("com.licel.jcardsim.utils.JavaCardApiProcessor")
        args(javacardApiStaging.get().asFile.absolutePath)
        inputs.dir(javacardApiStaging)
        outputs.dir(javacardApiStaging)
    }

val collectJcapi =
    tasks.register<Copy>("collectJcapi") {
        dependsOn(processJavacardApi)
        from(javacardApiStaging) {
            include("javacard/**", "javacardx/**")
        }
        into(jcapiDir)
    }

sourceSets {
    named("main") {
        output.dir(mapOf("builtBy" to collectJcapi), jcapiDir)
    }
}

val agentJar =
    tasks.register<Jar>("agentJar") {
        archiveBaseName = "sim-agent"
        from(sourceSets["main"].output)
        manifest { attributes("Premain-Class" to "org.qntx.card.sim.Agent") }
    }

configurations.create("agent") {
    isCanBeConsumed = true
    isCanBeResolved = false
    attributes {
        attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage.JAVA_RUNTIME))
        attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, objects.named(LibraryElements.JAR))
    }
}

artifacts {
    add("agent", agentJar.flatMap { it.archiveFile })
}

tasks.test {
    useJUnitPlatform()
    dependsOn(agentJar)
    jvmArgumentProviders.add(
        CommandLineArgumentProvider {
            listOf("-javaagent:${agentJar.get().archiveFile.get().asFile.absolutePath}=org/qntx/card/sim/probe")
        }
    )
}
