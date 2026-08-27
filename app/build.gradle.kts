plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// --- Unique-per-build identity ------------------------------------------------
// Every build gets a distinct application id + label so that this fusion.apk and
// any future fusion.apk install in PARALLEL instead of replacing each other.
// CI passes -PfusionBuildId=<run number>; local builds fall back to a timestamp.
val fusionBuildId: String =
    (project.findProperty("fusionBuildId") as String?)?.trim()?.takeIf { it.isNotEmpty() }
        ?: (System.currentTimeMillis() / 1000L).toString().takeLast(6)

android {
    namespace = "com.fusion.firewall"
    compileSdk = 34

    defaultConfig {
        // Base id + a unique suffix -> e.g. com.fusion.firewall.v123456
        applicationId = "com.fusion.firewall"
        applicationIdSuffix = ".v$fusionBuildId"
        // Wide compatibility: Android 5.0 (Lollipop) through Android 14. Newer
        // APIs are guarded at runtime so the APK parses and installs on legacy
        // devices too.
        minSdk = 21
        // Target 33 (Android 13): avoids the API-34-only foreground-service-type
        // manifest constructs that make Android 13-and-below reject the package.
        // The app still installs and runs on Android 14.
        targetSdk = 33
        versionCode = 1
        versionName = "1.0.$fusionBuildId"

        resValue("string", "app_label", "Fusion $fusionBuildId")
        resValue("string", "vpn_session", "Fusion $fusionBuildId")

        vectorDrawables { useSupportLibrary = true }
    }

    // Signing key. CI generates app/fusion.keystore at build time (it is never
    // committed). When present it is used; otherwise the build falls back to the
    // standard debug key so a local `assembleRelease` still produces an
    // installable APK. Parallel installs never collide because each build has a
    // unique application id, independent of the signature.
    val keystoreFile = file("fusion.keystore")
    signingConfigs {
        create("shared") {
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                storePassword = (project.findProperty("fusionStorePassword") as String?) ?: "fusion123"
                keyAlias = (project.findProperty("fusionKeyAlias") as String?) ?: "fusion"
                keyPassword = (project.findProperty("fusionKeyPassword") as String?) ?: "fusion123"
            }
            // Sign with the legacy JAR scheme (v1) as well as v2/v3 so devices on
            // Android 5–6 can verify the package (avoids "problem parsing").
            enableV1Signing = true
            enableV2Signing = true
        }
    }

    buildTypes {
        val signWith =
            if (keystoreFile.exists()) signingConfigs.getByName("shared")
            else signingConfigs.getByName("debug")
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signWith
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
