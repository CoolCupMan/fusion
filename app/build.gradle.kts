plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.fusion.firewall"
    compileSdk = 34

    defaultConfig {
        // Base application id. Product-flavor "slots" append a suffix so that
        // several builds (and future versions) can be installed side by side.
        applicationId = "com.fusion.firewall"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        vectorDrawables { useSupportLibrary = true }
    }

    // --- Parallel / future installs -----------------------------------------
    // Each slot produces a distinct applicationId + launcher label, so you can
    // keep multiple Fusion builds installed at the same time and A/B test new
    // versions without uninstalling the old one.
    flavorDimensions += "slot"
    productFlavors {
        create("slotA") {
            dimension = "slot"
            applicationIdSuffix = ".slota"
            resValue("string", "app_label", "Fusion")
            resValue("string", "vpn_session", "Fusion (A)")
        }
        create("slotB") {
            dimension = "slot"
            applicationIdSuffix = ".slotb"
            versionNameSuffix = "-B"
            resValue("string", "app_label", "Fusion B")
            resValue("string", "vpn_session", "Fusion (B)")
        }
        create("slotC") {
            dimension = "slot"
            applicationIdSuffix = ".slotc"
            versionNameSuffix = "-C"
            resValue("string", "app_label", "Fusion C")
            resValue("string", "vpn_session", "Fusion (C)")
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
            isShrinkResources = false
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
