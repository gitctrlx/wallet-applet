plugins {
    java
    alias(libs.plugins.pitest)
}

description = "Simulator, vector and mutation tests of the qntx card applet"

val agent: Configuration by configurations.creating
val cap = project(":applet").layout.buildDirectory.file("cap/qntx-card.cap")
val vectorGen: SourceSet by sourceSets.creating {
    java.srcDir(rootProject.layout.projectDirectory.dir("spec/vectors/gen/java"))
}

dependencies {
    agent(project(path = ":sim", configuration = "agent"))
    testImplementation(project(":sim"))
    testImplementation(project(":applet"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    "vectorGenImplementation"(libs.bouncycastle.prov)
}

tasks.test {
    useJUnitPlatform()
    dependsOn(":applet:cap")
    inputs.file(cap).withPropertyName("cap")
    inputs.files(agent).withPropertyName("agent")
    jvmArgumentProviders.add { listOf("-javaagent:${agent.singleFile.absolutePath}") }
    systemProperty("qntx.cap", cap.get().asFile.absolutePath)
    systemProperty(
        "qntx.reports",
        layout.buildDirectory
            .dir("reports")
            .get()
            .asFile.absolutePath,
    )
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    finalizedBy(memoryReport)
}

val memoryReport by tasks.registering {
    description = "Prints the simulator's transient-memory report of the installed applet."
    val report = layout.buildDirectory.file("reports/memory.txt")
    doLast {
        val file = report.get().asFile
        if (file.exists()) println(file.readText())
    }
}

val generateVectors by tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Writes every vector file of spec/protocol.md section 18 with the Java generator."
    val out = layout.buildDirectory.dir("vectors/java")
    classpath = vectorGen.runtimeClasspath
    mainClass = "org.qntx.card.vectors.Generate"
    argumentProviders.add { listOf(out.get().asFile.absolutePath) }
    outputs.dir(out)
}

pitest {
    pitestVersion =
        libs.versions.pit.core
            .get()
    junit5PluginVersion =
        libs.versions.pit.junit5
            .get()
    targetClasses = listOf("org.qntx.card.WalletApplet")
    targetTests = listOf("org.qntx.card.tests.*")
    additionalMutableCodePaths =
        listOf(
            project(":applet")
                .layout.buildDirectory
                .dir("classes/java/main")
                .get()
                .asFile,
        )
    jvmArgs =
        provider {
            listOf(
                "-javaagent:${agent.singleFile.absolutePath}",
                "-Dqntx.cap=${cap.get().asFile.absolutePath}",
                "-Dqntx.reports=${layout.buildDirectory.dir("reports").get().asFile.absolutePath}",
            )
        }
    mutators = listOf("STRONGER")
    mutationThreshold = 100
    timestampedReports = false
    outputFormats = listOf("HTML", "XML")
}

tasks.named("pitest") { dependsOn(":applet:cap", agent) }
