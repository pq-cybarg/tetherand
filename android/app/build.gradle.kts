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
    // M10.x ModelUpdater hybrid signature verify. Android stdlib's
    // java.security.Signature has no ML-DSA family — BouncyCastle
    // (1.78+) provides it. Combined with the stock SunEC / AndroidEC
    // providers for ECDSA-P256, the verifier walks both signatures
    // (classical + post-quantum, NIST level 5) per the strict
    // hybrid posture documented in ModelUpdater.kt.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
