package net.portswigger.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks scanner tasks started via MCP so agents can list/status/delete them.
 * Montoya does not expose a global "list all scan tasks" API.
 */
object ScanTaskRegistry {
    data class Entry(
        val id: String,
        val kind: String,
        val label: String,
        val task: ScanTask,
        val startedAtMs: Long = System.currentTimeMillis(),
    )

    private val tasks = ConcurrentHashMap<String, Entry>()

    fun register(kind: String, label: String, task: ScanTask): Entry {
        val id = UUID.randomUUID().toString().take(8)
        val entry = Entry(id = id, kind = kind, label = label, task = task)
        tasks[id] = entry
        return entry
    }

    fun get(id: String): Entry? = tasks[id]

    fun remove(id: String): Entry? = tasks.remove(id)

    fun list(): List<Entry> = tasks.values.sortedByDescending { it.startedAtMs }

    fun snapshot(entry: Entry): String {
        val t = entry.task
        return buildString {
            appendLine("taskId: ${entry.id}")
            appendLine("kind: ${entry.kind}")
            appendLine("label: ${entry.label}")
            appendLine("statusMessage: ${t.statusMessage()}")
            appendLine("requestCount: ${t.requestCount()}")
            appendLine("errorCount: ${t.errorCount()}")
            appendLine("startedAtMs: ${entry.startedAtMs}")
        }.trimEnd()
    }
}
