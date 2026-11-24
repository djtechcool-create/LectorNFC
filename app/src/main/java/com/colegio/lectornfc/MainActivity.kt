package com.colegio.lectornfc

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity(), NfcAdapter.ReaderCallback {

    private var adapter: NfcAdapter? = null
    private lateinit var status: TextView
    private lateinit var result: TextView
    private lateinit var apduLog: TextView
    private val logText = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()

        status = TextView(this).apply {
            textSize = 18f; gravity = Gravity.CENTER; setPadding(pad, pad, pad, pad)
            setBackgroundColor(Color.parseColor("#E8F0FE")); setTextColor(Color.parseColor("#1A3D7C"))
        }
        result = TextView(this).apply { textSize = 15f; setTextIsSelectable(true); setPadding(0, pad, 0, pad) }
        apduLog = TextView(this).apply {
            textSize = 11f; typeface = Typeface.MONOSPACE; setTextIsSelectable(true)
            setTextColor(Color.parseColor("#444444"))
        }
        val copy = Button(this).apply {
            text = "Copiar todo"
            setOnClickListener {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("Lector NFC", result.text.toString() + "\n\n" + apduLog.text))
                Toast.makeText(this@MainActivity, "Copiado", Toast.LENGTH_SHORT).show()
            }
        }
        val logTitle = TextView(this).apply {
            text = "Comunicación con el chip (APDU)"; textSize = 16f; setTypeface(null, Typeface.BOLD)
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad)
            addView(status); addView(result); addView(copy); addView(logTitle); addView(apduLog)
        }
        setContentView(ScrollView(this).apply { addView(col) })

        adapter = NfcAdapter.getDefaultAdapter(this)
        status.text = if (adapter == null) "Este celular no tiene NFC" else "Acerca la tarjeta a la parte trasera del celular"
    }

    override fun onResume() {
        super.onResume()
        val a = adapter ?: return
        if (!a.isEnabled) status.text = "Activa el NFC en Ajustes y vuelve a la app"
        a.enableReaderMode(
            this, this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            Bundle()
        )
    }

    override fun onPause() {
        super.onPause()
        adapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag) {
        logText.setLength(0)
        ui { status.text = "Leyendo… no muevas la tarjeta"; result.text = ""; apduLog.text = "" }
        val iso = IsoDep.get(tag)
        if (iso == null) {
            ui {
                status.text = "Tarjeta NFC detectada (no es bancaria)"
                result.text = "UID: ${tag.id.hex()}\nTecnologías: ${tag.techList.joinToString { it.substringAfterLast('.') }}"
            }
            return
        }
        try {
            iso.connect()
            iso.timeout = 5000
            val r = EmvReader(iso) { line -> logText.append(line).append('\n') }.read()
            val text = format(r)
            ui {
                status.text = if (r.apps.isEmpty()) "No se encontró aplicación bancaria" else "¡Lectura completa!"
                result.text = text
                apduLog.text = logText
            }
        } catch (e: Exception) {
            ui {
                status.text = "Error: ${e.message ?: e.javaClass.simpleName}. Intenta de nuevo sin mover la tarjeta."
                apduLog.text = logText
            }
        } finally {
            try { iso.close() } catch (_: Exception) {}
        }
    }

    private fun format(r: EmvReader.Result): String = buildString {
        for (app in r.apps) {
            append("━━━ ${app.label.ifBlank { "Aplicación" }} ━━━\n")
            append("AID: ${app.aid}\n\n")

            val pan = Tlv.find(app.data, 0x5A)?.let { EmvTags.describe(0x5A, it.value) }
                ?: Tlv.find(app.data, 0x57)?.value?.hex("")?.substringBefore('D')?.let { EmvTags.formatPan(it) }
            val exp = Tlv.find(app.data, 0x5F24)?.value?.hex("")?.let { "${it.substring(2, 4)}/20${it.substring(0, 2)}" }
                ?: Tlv.find(app.data, 0x57)?.value?.hex("")?.substringAfter('D', "")?.takeIf { it.length >= 4 }
                    ?.let { "${it.substring(2, 4)}/20${it.substring(0, 2)}" }
            val name = Tlv.find(app.data, 0x5F20)?.let { String(it.value, Charsets.ISO_8859_1).trim() }

            append("💳 Número: ${pan ?: "no disponible"}\n")
            append("📅 Vence: ${exp ?: "no disponible"}\n")
            append("👤 Titular: ${name?.ifBlank { null } ?: "no viene en el chip"}\n\n")

            append("── Todos los datos del chip ──\n")
            val seen = HashSet<Int>()
            for (n in Tlv.flatten(app.data)) {
                if (!seen.add(n.tag)) continue
                append("[${n.tagHex}] ${EmvTags.name(n.tag)}\n   ${EmvTags.describe(n.tag, n.value)}\n")
            }
            append("\n── Información técnica ──\n")
            for ((k, v) in app.extras) append("$k: $v\n")

            append("\n── Historial de transacciones ──\n")
            if (app.transactions.isEmpty()) append("La tarjeta no tiene historial disponible\n")
            app.transactions.forEachIndexed { i, t -> append("#${i + 1}\n$t\n\n") }
            append("\n")
        }
        append("ℹ️ El CVV y el PIN no están guardados en el chip.")
    }

    private fun ui(block: () -> Unit) = runOnUiThread(block)
}
