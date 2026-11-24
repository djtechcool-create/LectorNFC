package com.colegio.lectornfc

/** Utilidades hexadecimales y decodificador BER-TLV (formato que usan las tarjetas EMV). */

fun ByteArray.hex(sep: String = " "): String = joinToString(sep) { "%02X".format(it) }

fun String.hexBytes(): ByteArray {
    val s = replace(" ", "")
    return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

class TlvNode(val tag: Int, val value: ByteArray, val children: List<TlvNode>) {
    val tagHex: String get() = "%X".format(tag)
}

object Tlv {
    fun parse(data: ByteArray): List<TlvNode> {
        val out = mutableListOf<TlvNode>()
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            if (b0 == 0x00 || b0 == 0xFF) { i++; continue } // relleno
            var tag = b0
            i++
            if ((b0 and 0x1F) == 0x1F) {
                while (i < data.size) {
                    val b = data[i].toInt() and 0xFF
                    tag = (tag shl 8) or b
                    i++
                    if ((b and 0x80) == 0) break
                }
            }
            if (i >= data.size) break
            var len = data[i].toInt() and 0xFF
            i++
            if ((len and 0x80) != 0) {
                val n = len and 0x7F
                len = 0
                repeat(n) {
                    if (i < data.size) { len = (len shl 8) or (data[i].toInt() and 0xFF); i++ }
                }
            }
            if (len < 0 || i + len > data.size) break
            val v = data.copyOfRange(i, i + len)
            i += len
            val constructed = (b0 and 0x20) != 0
            val kids = if (constructed) try { parse(v) } catch (e: Exception) { emptyList() } else emptyList()
            out += TlvNode(tag, v, kids)
        }
        return out
    }

    fun find(nodes: List<TlvNode>, tag: Int): TlvNode? {
        for (n in nodes) {
            if (n.tag == tag) return n
            find(n.children, tag)?.let { return it }
        }
        return null
    }

    fun findAll(nodes: List<TlvNode>, tag: Int): List<TlvNode> {
        val r = mutableListOf<TlvNode>()
        for (n in nodes) {
            if (n.tag == tag) r += n
            r += findAll(n.children, tag)
        }
        return r
    }

    /** Lista plana de todos los datos primitivos (no contenedores). */
    fun flatten(nodes: List<TlvNode>): List<TlvNode> {
        val r = mutableListOf<TlvNode>()
        for (n in nodes) {
            if (n.children.isEmpty()) r += n else r += flatten(n.children)
        }
        return r
    }

    /** Lee una lista DOL (tag + longitud, sin valor), como el PDOL o el formato del historial. */
    fun parseDol(data: ByteArray): List<Pair<Int, Int>> {
        val out = mutableListOf<Pair<Int, Int>>()
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            var tag = b0
            i++
            if ((b0 and 0x1F) == 0x1F) {
                while (i < data.size) {
                    val b = data[i].toInt() and 0xFF
                    tag = (tag shl 8) or b
                    i++
                    if ((b and 0x80) == 0) break
                }
            }
            if (i >= data.size) break
            out += tag to (data[i].toInt() and 0xFF)
            i++
        }
        return out
    }
}

/** Nombres legibles de las etiquetas EMV más comunes. */
object EmvTags {
    val names = mapOf(
        0x4F to "AID (identificador de aplicación)",
        0x50 to "Nombre de la aplicación",
        0x57 to "Pista 2 equivalente (Track 2)",
        0x5A to "Número de tarjeta (PAN)",
        0x5F20 to "Nombre del titular",
        0x5F24 to "Fecha de vencimiento",
        0x5F25 to "Fecha de activación",
        0x5F28 to "País del emisor",
        0x5F2D to "Idioma preferido",
        0x5F30 to "Código de servicio",
        0x5F34 to "Número de secuencia del PAN",
        0x82 to "AIP (perfil de la aplicación)",
        0x84 to "Nombre del archivo DF",
        0x87 to "Prioridad de la aplicación",
        0x8C to "CDOL1",
        0x8D to "CDOL2",
        0x8E to "Lista de métodos de verificación (CVM)",
        0x8F to "Índice de clave pública de la autoridad",
        0x90 to "Certificado de clave pública del emisor",
        0x92 to "Resto de clave del emisor",
        0x93 to "Datos de aplicación firmados",
        0x94 to "AFL (ubicación de los archivos)",
        0x9F07 to "Control de uso de la aplicación",
        0x9F08 to "Versión de la aplicación",
        0x9F0D to "IAC - por defecto",
        0x9F0E to "IAC - denegación",
        0x9F0F to "IAC - en línea",
        0x9F10 to "Datos de aplicación del emisor",
        0x9F11 to "Índice de tabla de códigos",
        0x9F12 to "Nombre preferido de la aplicación",
        0x9F17 to "Intentos de PIN restantes",
        0x9F1F to "Datos discrecionales de pista 1",
        0x9F26 to "Criptograma de la aplicación",
        0x9F27 to "Datos de información del criptograma",
        0x9F32 to "Exponente de clave del emisor",
        0x9F36 to "Contador de transacciones (ATC)",
        0x9F38 to "PDOL (datos que pide la tarjeta)",
        0x9F42 to "Moneda de la aplicación",
        0x9F44 to "Exponente de la moneda",
        0x9F46 to "Certificado de clave pública ICC",
        0x9F47 to "Exponente de clave ICC",
        0x9F49 to "DDOL",
        0x9F4A to "Lista de etiquetas de autenticación",
        0x9F4B to "Datos dinámicos firmados",
        0x9F4D to "Entrada del historial de transacciones",
        0x9F4F to "Formato del historial",
        0x9F69 to "Datos de autenticación de tarjeta",
        0x9F6C to "Calificadores de transacción de tarjeta",
        0x9F6E to "Datos de forma de dispositivo",
        0x9F7C to "Datos del cliente",
        0xBF0C to "Datos discrecionales del emisor (FCI)",
        0x9F02 to "Monto autorizado",
        0x9F03 to "Otro monto",
        0x9F1A to "País del terminal",
        0x5F2A to "Moneda de la transacción",
        0x9A to "Fecha de la transacción",
        0x9C to "Tipo de transacción",
        0x9F21 to "Hora de la transacción",
        0x9F4E to "Nombre del comercio",
    )

    private val ascii = setOf(0x50, 0x5F20, 0x9F12, 0x5F2D, 0x9F4E)

    fun name(tag: Int) = names[tag] ?: "Etiqueta desconocida"

    fun describe(tag: Int, v: ByteArray): String {
        val h = v.hex("")
        return when (tag) {
            in ascii -> String(v, Charsets.ISO_8859_1).trim()
            0x5A -> formatPan(h.trimEnd('F'))
            0x5F24, 0x5F25 -> if (h.length >= 6) "${h.substring(4, 6)}/${h.substring(2, 4)}/20${h.substring(0, 2)}" else h
            0x9A -> if (h.length >= 6) "${h.substring(4, 6)}/${h.substring(2, 4)}/20${h.substring(0, 2)}" else h
            0x5F28, 0x9F1A -> "${h.trimStart('0')} (${Countries.name(h)})"
            0x9F42, 0x5F2A -> "${h.trimStart('0')} (${Currencies.name(h)})"
            0x9F36 -> "${h.toLong(16)} transacciones"
            0x9F17 -> "${h.toLong(16)} intentos"
            0x9F02, 0x9F03 -> "%.2f".format((h.toLongOrNull() ?: 0L) / 100.0)
            0x57 -> {
                val t = h.trimEnd('F')
                val parts = t.split('D')
                if (parts.size >= 2 && parts[1].length >= 7)
                    "PAN ${formatPan(parts[0])} · vence ${parts[1].substring(2, 4)}/${parts[1].substring(0, 2)} · servicio ${parts[1].substring(4, 7)}"
                else t
            }
            else -> h.chunked(2).joinToString(" ")
        }
    }

    fun formatPan(p: String) = p.chunked(4).joinToString(" ")
}

object Countries {
    private val m = mapOf(
        "0484" to "México", "0724" to "España", "0840" to "Estados Unidos", "0032" to "Argentina",
        "0152" to "Chile", "0170" to "Colombia", "0604" to "Perú", "0218" to "Ecuador",
        "0862" to "Venezuela", "0858" to "Uruguay", "0600" to "Paraguay", "0068" to "Bolivia",
        "0076" to "Brasil", "0320" to "Guatemala", "0340" to "Honduras", "0222" to "El Salvador",
        "0558" to "Nicaragua", "0188" to "Costa Rica", "0591" to "Panamá", "0214" to "Rep. Dominicana",
        "0192" to "Cuba", "0630" to "Puerto Rico", "0826" to "Reino Unido", "0250" to "Francia",
        "0276" to "Alemania", "0380" to "Italia", "0620" to "Portugal", "0124" to "Canadá",
    )
    fun name(h: String) = m[h.padStart(4, '0').takeLast(4)] ?: "?"
}

object Currencies {
    private val m = mapOf(
        "0484" to "MXN peso mexicano", "0978" to "EUR euro", "0840" to "USD dólar", "0032" to "ARS peso argentino",
        "0152" to "CLP peso chileno", "0170" to "COP peso colombiano", "0604" to "PEN sol", "0937" to "VES bolívar",
        "0858" to "UYU peso uruguayo", "0600" to "PYG guaraní", "0068" to "BOB boliviano", "0986" to "BRL real",
        "0320" to "GTQ quetzal", "0340" to "HNL lempira", "0558" to "NIO córdoba", "0188" to "CRC colón",
        "0590" to "PAB balboa", "0214" to "DOP peso dominicano", "0826" to "GBP libra", "0124" to "CAD dólar canadiense",
    )
    fun name(h: String) = m[h.padStart(4, '0').takeLast(4)] ?: "?"
}
