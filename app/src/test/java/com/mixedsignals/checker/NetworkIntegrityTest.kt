package com.mixedsignals.checker

import com.mixedsignals.checker.data.integrity.GoogleTransparencyLog
import com.mixedsignals.checker.data.integrity.Http
import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.SignedNote
import com.mixedsignals.checker.domain.integrity.SourceParsers
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files

/** Kiểm thử với log thật trên Internet. Chỉ chạy khi đặt ATTR_NET=1. */
class NetworkIntegrityTest {
    private fun enabled() = assumeTrue(System.getenv("ATTR_NET") == "1")

    @Test fun findsAndProvesRealEntryInGoogleLog() {
        enabled()
        val base = GoogleTransparencyLog.BASE_URL
        val cp = SignedNote.verifyCheckpoint(String(Http.get("$base/checkpoint")), GoogleTransparencyLog.NOTE_KEY)
        // Lấy một bản ghi thật trong gói đầy đủ gần cuối log.
        val n = (cp.size - 1) / 256 - 1
        val bundle = SourceParsers.parseEntryBundle(Http.get("$base/tile/entries/" + SourceParsers.tileIndexPath(n)))
        val lines = String(bundle[100]).trim().lines()
        println("Bản ghi thật: $lines")
        val log = GoogleTransparencyLog(Files.createTempDirectory("tlog").toFile())
        val r = log.check(lines[0], lines[2], lines[3].toLong(), maxBundles = 4) { println(it) }
        println("${r.status} ${r.summary} ${r.details}")
        assertEquals(CheckStatus.PASS, r.status)
        // Cùng package + phiên bản nhưng hash khác phải bị phát hiện.
        val bad = log.check("0".repeat(64), lines[2], lines[3].toLong(), maxBundles = 4)
        assertEquals(CheckStatus.FAIL, bad.status)
    }
}
