plugins {
    java
}

description = "Reference host library written from spec/protocol.md (stage core)"

dependencies {
    implementation(libs.bouncycastle.prov)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jackson.jr)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    systemProperty("qntx.vectors", rootProject.file("spec/vectors").absolutePath)
}
