package com.colegio.lectornfc

import android.nfc.tech.IsoDep
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.random.Random

/**
 * Lee una tarjeta bancaria contactless siguiendo el estándar EMV:
 * 1. SELECT PPSE  -> lista de aplicaciones (Visa, Mastercard...)
 * 2. SELECT AID   -> elige la aplicación
 * 3. GET PROCESSING OPTIONS -> la tarjeta dice dónde están sus datos (AFL)
 * 4. READ RECORD  -> lee cada registro
 */
class EmvReader(private val iso: IsoDep, private val log: (String) -> Unit) {

    class Result(
        val apps: List<AppResult>,
    )

    class AppResult(
        val aid: String,
        val label: String,
        val data: List<TlvNode>,
        val extras: List<Pair<String, String>>,
        val transactions: List<String>,
    )

    private val knownAids = listOf(
        "A0000000031010" to "Visa", "A0000000032010" to "Visa Electron", "A0000000041010" to "Mastercard",
        "A0000000043060" to "Maestro", "A000000025010402" to "American Express", "A0000001523010" to "Discover",
        "A0000000651010" to "JCB", "A000000333010101" to "UnionPay",
    )

    private fun transceive(apdu: ByteArray, what: String): ByteArray {
        log("→ $what\n   ${apdu.hex()}")
        var r = iso.transceive(apdu)
        // 6Cxx: longitud incorrecta, reintentar con la correcta
        if (r.size == 2 && r[0] == 0x6C.toByte()) {
            val a = apdu.copyOf(); a[a.size - 1] = r[1]
            r = iso.transceive(a)
        }
        // 61xx: hay más datos, pedirlos con GET RESPONSE
        val out = java.io.ByteArrayOutputStream()
        while (r.size >= 2 && r[r.size - 2] == 0x61.toByte()) {
            out.write(r, 0, r.size - 2)
            r = iso.transceive(byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, r[r.size - 1]))
        }
        out.write(r)
        val res = out.toByteArray()
        log("← ${sw(res)}\n   ${res.hex()}")
        return res
    }

    private fun ok(r: ByteArray) = r.size >= 2 && r[r.size - 2] == 0x90.toByte() && r[r.size - 1] == 0x00.toByte()
    private fun body(r: ByteArray) = r.copyOfRange(0, maxOf(0, r.size - 2))
    private fun sw(r: ByteArray) = if (r.size >= 2) "SW " + r.copyOfRange(r.size - 2, r.size).hex("") else "sin respuesta"

    private fun select(aid: ByteArray, what: String): ByteArray =
        transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid + byteArrayOf(0x00), what)

    fun read(): Result {
        val apps = mutableListOf<Pair<String, String>>()
        val ppse = select("2PAY.SYS.DDF01".toByteArray(), "SELECT PPSE (¿qué aplicaciones tienes?)")
        if (ok(ppse)) {
            val nodes = Tlv.parse(body(ppse))
            for (entry in Tlv.findAll(nodes, 0x61)) {
                val aid = Tlv.find(entry.children, 0x4F)?.value?.hex("") ?: continue
                val label = Tlv.find(entry.children, 0x50)?.let { String(it.value, Charsets.ISO_8859_1) } ?: ""
                apps += aid to label
            }
        }
        if (apps.isEmpty()) {
            log("PPSE no respondió, probando AIDs conocidos…")
            for ((aid, name) in knownAids) {
                if (ok(select(aid.hexBytes(), "SELECT $name"))) { apps += aid to name; break }
            }
        }
        return Result(apps.map { (aid, label) -> readApp(aid, label) })
    }

    private fun readApp(aid: String, ppseLabel: String): AppResult {
        val all = mutableListOf<TlvNode>()
        val extras = mutableListOf<Pair<String, String>>()
        val fci = select(aid.hexBytes(), "SELECT AID $aid")
        val fciNodes = if (ok(fci)) Tlv.parse(body(fci)) else emptyList()
        all += fciNodes
        val label = Tlv.find(fciNodes, 0x50)?.let { String(it.value, Charsets.ISO_8859_1).trim() } ?: ppseLabel

        // GET PROCESSING OPTIONS con los datos que la tarjeta pide (PDOL)
        val pdol = Tlv.find(fciNodes, 0x9F38)?.value
        val pdolData = pdol?.let { buildPdol(Tlv.parseDol(it)) } ?: ByteArray(0)
        val gpoData = byteArrayOf(0x83, pdolData.size.toByte()) + pdolData
        val gpo = transceive(
            byteArrayOf(0x80.toByte(), 0xA8.toByte(), 0x00, 0x00, gpoData.size.toByte()) + gpoData + byteArrayOf(0x00),
            "GET PROCESSING OPTIONS"
        )
        var afl: ByteArray? = null
        if (ok(gpo)) {
            val b = body(gpo)
            if (b.isNotEmpty() && b[0] == 0x80.toByte()) {
                // Formato 1: AIP (2 bytes) + AFL
                val n = Tlv.parse(b).firstOrNull()?.value
                if (n != null && n.size > 2) {
                    all += TlvNode(0x82, n.copyOfRange(0, 2), emptyList())
                    afl = n.copyOfRange(2, n.size)
                    all += TlvNode(0x94, afl, emptyList())
                }
            } else {
                val nodes = Tlv.parse(b)
                all += nodes
                afl = Tlv.find(nodes, 0x94)?.value
            }
        }

        // READ RECORD según el AFL (o búsqueda si no hay AFL)
        if (afl != null && afl.size >= 4) {
            for (i in 0 until afl.size / 4) {
                val sfi = (afl[i * 4].toInt() and 0xFF) shr 3
                val first = afl[i * 4 + 1].toInt() and 0xFF
                val last = afl[i * 4 + 2].toInt() and 0xFF
                for (rec in first..last) readRecord(sfi, rec)?.let { all += it }
            }
        } else {
            log("Sin AFL: explorando archivos 1-10…")
            for (sfi in 1..10) for (rec in 1..10) {
                val r = readRecord(sfi, rec) ?: break
                all += r
            }
        }

        // GET DATA: contador de transacciones e intentos de PIN
        for ((tag, name) in listOf(0x9F36 to "contador de transacciones", 0x9F17 to "intentos de PIN", 0x9F13 to "último ATC en línea")) {
            try {
                val r = transceive(byteArrayOf(0x80.toByte(), 0xCA.toByte(), (tag shr 8).toByte(), tag.toByte(), 0x00), "GET DATA $name")
                if (ok(r)) all += Tlv.parse(body(r))
            } catch (e: Exception) { /* opcional */ }
        }

        // Historial de transacciones (si el banco lo habilitó)
        val txs = mutableListOf<String>()
        val logEntry = Tlv.find(all, 0x9F4D)?.value
        if (logEntry != null && logEntry.size >= 2) {
            val sfi = logEntry[0].toInt() and 0xFF
            val count = logEntry[1].toInt() and 0xFF
            val fmtResp = transceive(byteArrayOf(0x80.toByte(), 0xCA.toByte(), 0x9F.toByte(), 0x4F, 0x00), "GET DATA formato del historial")
            val fmt = if (ok(fmtResp)) Tlv.find(Tlv.parse(body(fmtResp)), 0x9F4F)?.value?.let { Tlv.parseDol(it) } else null
            for (rec in 1..count) {
                val r = transceive(byteArrayOf(0x00, 0xB2.toByte(), rec.toByte(), ((sfi shl 3) or 4).toByte(), 0x00), "READ RECORD historial #$rec")
                if (!ok(r)) break
                val b = body(r)
                if (fmt == null) { txs += b.hex(); continue }
                var p = 0
                val parts = mutableListOf<String>()
                for ((t, l) in fmt) {
                    if (p + l > b.size) break
                    parts += "${EmvTags.name(t)}: ${EmvTags.describe(t, b.copyOfRange(p, p + l))}"
                    p += l
                }
                txs += parts.joinToString("\n")
            }
        }

        extras += "Tecnología" to iso.tag.techList.joinToString { it.substringAfterLast('.') }
        extras += "UID del chip" to iso.tag.id.hex()
        iso.historicalBytes?.let { extras += "Bytes históricos" to it.hex() }

        return AppResult(aid, label, all, extras, txs)
    }

    private fun readRecord(sfi: Int, rec: Int): List<TlvNode>? {
        val r = transceive(byteArrayOf(0x00, 0xB2.toByte(), rec.toByte(), ((sfi shl 3) or 4).toByte(), 0x00), "READ RECORD archivo $sfi registro $rec")
        return if (ok(r)) Tlv.parse(body(r)) else null
    }

    /** Rellena los datos que la tarjeta pide en el PDOL con valores de un "terminal" de prueba. */
    private fun buildPdol(dol: List<Pair<Int, Int>>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val today = SimpleDateFormat("yyMMdd", Locale.US).format(Date()).hexBytes()
        for ((tag, len) in dol) {
            val v: ByteArray = when (tag) {
                0x9F66 -> "36004000".hexBytes()          // capacidades del lector contactless
                0x9F02 -> "000000000100".hexBytes()      // monto 1.00
                0x9F03 -> "000000000000".hexBytes()
                0x9F1A -> "0484".hexBytes()              // país
                0x5F2A -> "0484".hexBytes()              // moneda
                0x9A -> today
                0x9C -> byteArrayOf(0x00)
                0x9F37 -> Random.nextBytes(4)            // número aleatorio
                0x9F35 -> byteArrayOf(0x22)
                0x9F33 -> "E0F8C8".hexBytes()
                0x9F40 -> "6000F0A001".hexBytes()
                else -> ByteArray(len)
            }
            out.write(ByteArray(len) { if (it < v.size) v[it] else 0 })
        }
        return out.toByteArray()
    }
}
