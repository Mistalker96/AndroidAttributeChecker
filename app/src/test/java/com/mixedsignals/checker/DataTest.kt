package com.mixedsignals.checker

import com.mixedsignals.checker.data.ApkSignatureReader
import com.mixedsignals.checker.data.CertParser
import com.mixedsignals.checker.data.PlayStoreSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DataTest {

    // ---------- Tách subject chứng chỉ ----------

    @Test fun parsesRfc2253WithEscapesAndHex() {
        val email = "android@android.com".toByteArray().joinToString("") { "%02x".format(it) }
        val dn = "EMAILADDRESS=#1613$email,CN=Cube Apps\\, Ltd,OU=,O=\"Acme + Co\",L=H\\C3\\A0 N\\E1\\BB\\99i,C=VN"
        val m = CertParser.parseRfc2253(dn)
        assertEquals("android@android.com", m["EMAILADDRESS"])
        assertEquals("Cube Apps, Ltd", m["CN"])
        assertEquals("Acme + Co", m["O"])
        assertEquals("Hà Nội", m["L"])
        assertEquals("VN", m["C"])
        assertNull("Trường rỗng phải bị bỏ", m["OU"])
    }

    @Test fun parsesX500PrincipalThroughJavaApi() {
        val p = javax.security.auth.x500.X500Principal("CN=Jane, OU=Mobile, O=Acme Ltd, L=Hanoi, ST=Hanoi, C=VN")
        val m = CertParser.parseDn(p)
        assertEquals(listOf("CN", "OU", "O", "L", "ST", "C"), m.keys.toList())
        assertEquals("Acme Ltd", m["O"])
    }

    // ---------- Phát hiện scheme chữ ký ----------

    private fun zipBytes(vararg names: String): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for (n in names) {
                z.putNextEntry(ZipEntry(n)); z.write("x".toByteArray()); z.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    /** Chèn một APK Signing Block chứa các cặp (id, value) ngay trước Central Directory. */
    private fun withSigningBlock(zip: ByteArray, pairs: List<Pair<Int, ByteArray>>): ByteArray {
        val eocd = (zip.size - 22 downTo 0).first {
            ByteBuffer.wrap(zip, it, 4).order(ByteOrder.LITTLE_ENDIAN).int == 0x06054b50
        }
        val cdOffset = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN).getInt(eocd + 16)
        val pairsLen = pairs.sumOf { 8 + 4 + it.second.size }
        val blockSize = (pairsLen + 8 + 16).toLong() // không tính trường size đầu tiên
        val block = ByteBuffer.allocate((blockSize + 8).toInt()).order(ByteOrder.LITTLE_ENDIAN)
        block.putLong(blockSize)
        for ((id, v) in pairs) {
            block.putLong((4 + v.size).toLong()); block.putInt(id); block.put(v)
        }
        block.putLong(blockSize)
        block.put("APK Sig Block 42".toByteArray())
        val blockBytes = block.array()
        val out = ByteArrayOutputStream()
        out.write(zip, 0, cdOffset)
        out.write(blockBytes)
        out.write(zip, cdOffset, zip.size - cdOffset)
        val result = out.toByteArray()
        val newEocd = eocd + blockBytes.size
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(newEocd + 16, cdOffset + blockBytes.size)
        return result
    }

    private fun tmp(bytes: ByteArray): File = File.createTempFile("test", ".apk").apply {
        deleteOnExit(); writeBytes(bytes)
    }

    @Test fun detectsV2AndV3FromSigningBlock() {
        val apk = withSigningBlock(
            zipBytes("AndroidManifest.xml", "classes.dex"),
            listOf(ApkSignatureReader.ID_V2 to ByteArray(4), ApkSignatureReader.ID_V3 to ByteArray(4), 0x42726577 to ByteArray(8)),
        )
        val r = ApkSignatureReader.read(tmp(apk))
        assertEquals(setOf(2, 3), r.schemes)
    }

    @Test fun detectsV1FromSfFile() {
        val r = ApkSignatureReader.read(tmp(zipBytes("AndroidManifest.xml", "META-INF/MANIFEST.MF", "META-INF/CERT.SF")))
        assertEquals(setOf(1), r.schemes)
    }

    @Test fun plainZipHasNoScheme() {
        assertTrue(ApkSignatureReader.read(tmp(zipBytes("a.txt"))).schemes.isEmpty())
    }

    /** Chạy trên APK thật nếu đặt biến môi trường ATTR_TEST_APK (ví dụ APK debug vừa build). */
    @Test fun readsRealApkWhenProvided() {
        val path = System.getenv("ATTR_TEST_APK")
        assumeTrue(path != null && File(path).exists())
        val r = ApkSignatureReader.read(File(path!!))
        println("Schemes=${r.schemes} signers=${r.signerCount}")
        assertTrue(r.schemes.isNotEmpty())
        val c = CertParser.fromX509(r.signerCerts.first())
        println("Subject=${c.subjectString} sha256=${c.sha256}")
        System.getenv("ATTR_TEST_SHA256")?.let { assertEquals(it.lowercase().replace(":", ""), c.sha256) }
    }

    // ---------- Đọc trang Google Play ----------

    @Test fun parsesPlayHtmlSnippet() {
        val html = """
            <meta property="og:title" content="Signal Private Messenger - Apps on Google Play">
            <a href="/store/apps/developer?id=Signal+Foundation"><span>Signal Foundation</span></a>
            <a class="x" href="https://signal.org" target="_blank" aria-label="Website https://signal.org will open in a new window or tab.">
            <a href="mailto:support@signal.org">
            <a class="y" href="https://signal.org/privacy" target="_blank" aria-label="Privacy Policy https://signal.org/privacy will open">
            ["Spotify AB",["support@spotify.com"],["Regeringsgatan 19\n111 53 Stockholm\nSweden"],"+46"]
        """.trimIndent()
        val m = PlayStoreSource.parse(html)
        assertEquals("Signal Private Messenger", m.appName)
        assertEquals("Signal Foundation", m.developerName)
        assertEquals("https://signal.org", m.website)
        assertEquals("support@signal.org", m.email)
        assertEquals("https://signal.org/privacy", m.privacyPolicyUrl)
        assertEquals("Regeringsgatan 19, 111 53 Stockholm, Sweden", m.address)
        assertEquals("play", m.source)
    }
}
