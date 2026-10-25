import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Khóa ký bản release nằm ngoài mã nguồn (keystore.properties + release.jks).
// Nếu chưa có, bản release sẽ không được ký.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.mixedsignals.checker"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.mixedsignals.checker"
        minSdk = 28
        targetSdk = 36
        versionCode = 2
        versionName = "2.0.0"
    }

    signingConfigs {
        if (keystoreProps.containsKey("storeFile")) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
                // Ký cả v2 và v3 (v3 cho phép xoay khóa sau này, §5.2).
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            // Tệp metadata trùng lặp trong các jar BouncyCastle.
            excludes += setOf("META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.02.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // Xác minh đầy đủ chữ ký APK (v1–v3.1), lineage và Source Stamp.
    implementation("com.android.tools.build:apksig:8.12.0")
    // Ed25519 để xác minh checkpoint của transparency log Google (minSdk 28 chưa có sẵn Ed25519).
    implementation("org.bouncycastle:bcprov-jdk18on:1.80.2")

    testImplementation("junit:junit:4.13.2")
    // org.json có sẵn trên Android nhưng không có trên JVM khi chạy unit test.
    testImplementation("org.json:json:20240303")
    // Tạo chứng chỉ X.509 để kiểm thử Code Transparency.
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.80.2")
}
