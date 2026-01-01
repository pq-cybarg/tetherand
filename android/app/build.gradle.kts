plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
}

android {
    namespace = "dev.tetherand.app"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.tetherand.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions { jvmTarget = "21" }

    ksp {
        arg("room.schemaLocation", "$projectDir/schemas")
    }

    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    packaging {
        resources.excludes += listOf("META-INF/LICENSE*", "META-INF/NOTICE*")
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // M7a threat detection
    implementation("app.netmonster:core:1.3.0")
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")
    // M10 AI-era defenses — LiteRT (formerly TFLite) for the contributory
    // classifier layer + WorkManager for the OSINT periodic refresh
    // through Privacy Chain. NoOp-safe when models are not bundled —
    // deterministic primaries run with zero dependency on these libs.
    implementation("org.tensorflow:tensorflow-lite:2.16.1")
    implementation("org.tensorflow:tensorflow-lite-support:0.4.4")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    // M10.x ModelUpdater quadruple-signature verify. Android stdlib's
    // java.security.Signature lacks the PQ families — BouncyCastle 1.80+
    // provides ML-DSA-87 (FIPS 204 lattice) and SLH-DSA-SHA2-256s
    // (FIPS 205 hash-based). Combined with stock EC providers for
    // ECDSA-P521 (NIST L5 classical) and Ed448 (~L4 Edwards classical,
    // non-NIST origin), the verifier walks all four signatures —
    // "highest security available across diverse cryptographic
    // assumptions". See ModelUpdater.kt for the full rationale.
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    // Apache Milagro AMCL — pure-Java BLS12-381 implementation.
    // Used by PublicBeacons to verify drand-quicknet round signatures
    // (BLS12-381 G1 pubkey × G2 signature, pairing-check verification).
    // Pure Java with no native bindings; ~500 KB binary cost in
    // exchange for full BLS verification of every drand round we
    // absorb into the SeekerRng mixer.
    //
    // Exclusion: milagro 0.4.0 transitively pulls guava 23.0, which
    // conflicts with newer guava (com.google.guava:listenablefuture
    // is the modern carve-out) producing a Duplicate-class build
    // failure. Milagro itself doesn't use ListenableFuture in the
    // BLS code path we exercise, so dropping it is safe.
    implementation("org.miracl.milagro.amcl:milagro-crypto-java:0.4.0") {
        exclude(group = "com.google.guava", module = "guava")
    }
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
