package com.mixedsignals.checker.data.integrity

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.android.apksig.ApkVerifier
import com.mixedsignals.checker.data.CertParser
import com.mixedsignals.checker.domain.integrity.ApkEvidence
import com.mixedsignals.checker.domain.integrity.CodeTransparency
import com.mixedsignals.checker.domain.integrity.KeySibling
import com.mixedsignals.checker.domain.integrity.ProtectedComponent
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/** Một APK đã sẵn sàng để kiểm: file chính (base) và các split có mặt. */
data class ApkBundle(
    val displayName: String,
    val base: File,
    val splits: List<File>,
    val installedPackage: String? = null,
)

/** Kết quả đọc APK: bằng chứng + dữ liệu cho Code Transparency. */
data class InspectedApk(
    val evidence: ApkEvidence,
    val ctJws: String?,
    val ctEntries: Map<String, Map<String, String>>,
)

class ApkInspector(private val context: Context) {
    private val pm: PackageManager = context.packageManager

    /** Chép file người dùng chọn vào cache. Hỗ trợ .apk và gói chia nhỏ .apks / .xapk (ZIP chứa nhiều APK). */
    fun prepareFromUri(uri: Uri, displayName: String): ApkBundle {
        val dir = File(context.cacheDir, "integrity").apply { deleteRecursively(); mkdirs() }
        val raw = File(dir, "input.bin")
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Không mở được file" }
            raw.outputStream().use { input.copyTo(it) }
        }
        val innerApks = runCatching { ZipFile(raw).use { z -> z.entries().asSequence().map { it.name }.filter { it.endsWith(".apk") && !it.contains('/') }.toList() } }
            .getOrDefault(emptyList())
        if (innerApks.isEmpty()) {
            val apk = File(dir, "base.apk"); raw.renameTo(apk)
            return ApkBundle(displayName, apk, emptyList())
        }
        // Gói .apks/.xapk: giải nén các APK con.
        val files = ZipFile(raw).use { z ->
            innerApks.map { name ->
                File(dir, name).also { f -> z.getInputStream(z.getEntry(name)).use { i -> f.outputStream().use { i.copyTo(it) } } }
            }
        }
        val base = files.firstOrNull { it.name == "base.apk" }
            ?: files.firstOrNull { !it.name.startsWith("config.") && !it.name.startsWith("split_") }
            ?: files.maxBy { it.length() }
        return ApkBundle(displayName, base, files - base)
    }

    fun prepareInstalled(packageName: String): ApkBundle {
        val ai = pm.getApplicationInfo(packageName, 0)
        val splits = ai.splitSourceDirs.orEmpty().map(::File)
        return ApkBundle(ai.loadLabel(pm).toString(), File(ai.sourceDir), splits, packageName)
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(path: String): PackageInfo? {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return if (Build.VERSION.SDK_INT >= 33) pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getPackageArchiveInfo(path, flags)
    }

    @Suppress("DEPRECATION")
    private fun installedInfo(pkg: String): PackageInfo {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getPackageInfo(pkg, flags)
    }

    fun inspect(bundle: ApkBundle): InspectedApk {
        val base = bundle.base
        // 1. Xác minh chữ ký đầy đủ bằng apksig (thư viện chính thức của Android SDK).
        val vr = runCatching { ApkVerifier.Builder(base).build().verify() }
        val result = vr.getOrNull()
        val schemes = buildSet {
            if (result?.isVerifiedUsingV1Scheme == true) add(1)
            if (result?.isVerifiedUsingV2Scheme == true) add(2)
            if (result?.isVerifiedUsingV3Scheme == true) add(3)
            if (result?.isVerifiedUsingV31Scheme == true) add(31)
        }
        val signerCerts = result?.signerCertificates.orEmpty().map { CertParser.fromX509(it) }
        val lineage = runCatching { result?.signingCertificateLineage?.certificatesInLineage.orEmpty().map { CertParser.fromX509(it) } }
            .getOrDefault(emptyList())
        val errors = result?.allErrors?.map { it.toString() } ?: listOf("Không đọc được APK: ${vr.exceptionOrNull()?.message}")
        val stamp = result?.sourceStampInfo

        // 2. Manifest: package, phiên bản, quyền, thành phần cần quyền đặc biệt, cờ nguy hiểm.
        val pi = bundle.installedPackage?.let { installedInfo(it) } ?: archiveInfo(base.path)
        val ai = pi?.applicationInfo?.also { if (bundle.installedPackage == null) { it.sourceDir = base.path; it.publicSourceDir = base.path } }
        val pkg = pi?.packageName ?: "(không đọc được manifest)"
        val components = buildList {
            pi?.services?.forEach { s -> s.permission?.let { add(ProtectedComponent(s.name, it)) } }
            pi?.receivers?.forEach { r -> r.permission?.let { add(ProtectedComponent(r.name, it)) } }
        }

        // 3. Dữ liệu cho Code Transparency: hash các file .dex/.so trong mọi APK có mặt.
        var jws: String? = null
        val entries = LinkedHashMap<String, Map<String, String>>()
        for (f in listOf(base) + bundle.splits) {
            runCatching {
                ZipFile(f).use { z ->
                    if (f == base) z.getEntry(CodeTransparency.ENTRY_NAME)?.let { e -> jws = z.getInputStream(e).use { String(it.readBytes()) } }
                    val m = LinkedHashMap<String, String>()
                    for (e in z.entries()) {
                        if (e.isDirectory || !(e.name.endsWith(".dex") || e.name.endsWith(".so"))) continue
                        m[e.name] = z.getInputStream(e).use { sha256Stream(it) }
                    }
                    entries[f.name] = m
                }
            }
        }

        val evidence = ApkEvidence(
            fileName = bundle.displayName,
            fileSha256 = sha256File(base),
            fileSize = base.length(),
            packageName = pkg,
            label = ai?.loadLabel(pm)?.toString() ?: pkg,
            versionName = pi?.versionName,
            versionCode = pi?.longVersionCode ?: 0,
            minSdk = ai?.minSdkVersion,
            targetSdk = ai?.targetSdkVersion,
            debuggable = ai != null && (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            usesCleartextTraffic = ai != null && (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0,
            requestedPermissions = pi?.requestedPermissions?.toList().orEmpty(),
            protectedComponents = components,
            signatureVerified = result?.isVerified == true,
            signatureErrors = errors,
            schemes = schemes,
            signerCerts = signerCerts,
            lineageCerts = lineage,
            sourceStampPresent = stamp != null,
            sourceStampVerified = result?.isSourceStampVerified == true,
            installed = bundle.installedPackage != null,
            installer = bundle.installedPackage?.let { installerOf(it) },
            implicitPermissions = implicitOf(pi),
        )
        return InspectedApk(evidence, jws, entries)
    }

    /** Quyền có cờ REQUESTED_PERMISSION_IMPLICIT (API 31+): hệ thống tự thêm, app không khai báo. */
    private fun implicitOf(pi: PackageInfo?): Set<String> {
        if (pi == null || Build.VERSION.SDK_INT < 31) return emptySet()
        val names = pi.requestedPermissions ?: return emptySet()
        val flags = pi.requestedPermissionsFlags ?: return emptySet()
        return names.indices.filter { flags.getOrElse(it) { 0 } and PackageInfo.REQUESTED_PERMISSION_IMPLICIT != 0 }.map { names[it] }.toSet()
    }

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName else pm.getInstallerPackageName(pkg)
    }.getOrNull()

    /** App khác trên máy được ký bằng một trong các khóa [fingerprints] (khóa dùng chung). Null nếu không quét được. */
    @Suppress("DEPRECATION")
    fun siblingsSignedWith(fingerprints: Set<String>): List<KeySibling>? = runCatching {
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val pkgs = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else pm.getInstalledPackages(flags)
        pkgs.filter { p ->
            p.packageName != context.packageName &&
                p.signingInfo?.apkContentsSigners.orEmpty().any { sha256(it.toByteArray()) in fingerprints }
        }.map { p -> KeySibling(p.packageName, p.applicationInfo?.loadLabel(pm)?.toString() ?: p.packageName) }
    }.getOrNull()

    /** Danh sách app đã cài để người dùng chọn kiểm tra. */
    @Suppress("DEPRECATION")
    fun installedApps(includeSystem: Boolean): List<KeySibling> {
        val pkgs = if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L)) else pm.getInstalledPackages(0)
        return pkgs.mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            if (p.packageName == context.packageName || (system && !includeSystem)) null
            else KeySibling(p.packageName, ai.loadLabel(pm).toString())
        }.sortedBy { it.label.lowercase() }
    }

    companion object {
        fun sha256(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

        fun sha256File(f: File): String = f.inputStream().use { sha256Stream(it) }

        /** Băm theo luồng để không phải nạp cả file lớn (thư viện .so, APK) vào bộ nhớ. */
        fun sha256Stream(input: java.io.InputStream): String {
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(1 shl 16)
            while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) }
            return md.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
