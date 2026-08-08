package net.portswigger.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks scanner tasks started via MCP so agents can list/status/delete them.
 * Montoya does not expose a global "list all scan tasks" API.
 *
 * Note on Burp API gaps: the public [ScanTask] / [burp.api.montoya.scanner.Crawl]
 * implementation ships with `statusMessage()` / `requestCount()` / `errorCount()`
 * that throw `UnsupportedOperationException` at runtime on some builds. Burp's own
 * AT avoids this by using an *internal* engine-task id rather than the public
 * `Crawl` object. Since that internal path is not exposed via Montoya, we (a)
 * never let a stubbed method fail the snapshot, and (b) accept an optional
 * [ProgressProvider] so a crawl's real progress can be observed from the Site Map
 * — the same surface Burp's AT tells its agent to query (`list_sitemap`).
 */
object ScanTaskRegistry {
    data class Entry(
        val id: String,
        val kind: String,
        val label: String,
        val task: ScanTask,
        val startedAtMs: Long = System.currentTimeMillis(),
        /**
         * Optional real-progress probe. For crawl tasks this counts Site Map
         * request/response pairs under the seed URL prefix, since the `Crawl`
         * object's own counters are stubbed on some Burp builds.
         */
        val progressProvider: (() -> Progress?)? = null,
    )

    /** Observable progress, used to compensate for stubbed [ScanTask] counters. */
    data class Progress(
        val observedRequestCount: Int,
        val detail: String? = null,
    )

    private val tasks = ConcurrentHashMap<String, Entry>()

    fun register(
        kind: String,
        label: String,
        task: ScanTask,
        progressProvider: (() -> Progress?)? = null,
    ): Entry {
        val id = UUID.randomUUID().toString().take(8)
        val entry = Entry(id = id, kind = kind, label = label, task = task, progressProvider = progressProvider)
        tasks[id] = entry
        return entry
    }

    fun get(id: String): Entry? = tasks[id]

    fun remove(id: String): Entry? = tasks.remove(id)

    fun list(): List<Entry> = tasks.values.sortedByDescending { it.startedAtMs }

    fun snapshot(entry: Entry): String {
        val statusMessage = safe("statusMessage") { entry.task.statusMessage() }
        // Prefer the provider's real count when the ScanTask counter is stubbed/zero.
        val progress = entry.progressProvider?.invoke()
        val requestCount = when {
            progress != null -> progress.observedRequestCount.toString()
            else -> safeCount("requestCount") { entry.task.requestCount() }
        }
        val errorCount = safeCount("errorCount") { entry.task.errorCount() }
        val elapsed = (System.currentTimeMillis() - entry.startedAtMs) / 1000

        return buildString {
            appendLine("taskId: ${entry.id}")
            appendLine("kind: ${entry.kind}")
            appendLine("label: ${entry.label}")
            appendLine("statusMessage: $statusMessage")
            appendLine("requestCount: $requestCount")
            appendLine("errorCount: $errorCount")
            appendLine("elapsedSeconds: $elapsed")
            if (progress != null && progress.detail != null) {
                appendLine("progress: ${progress.detail}")
            }
        }.trimEnd()
    }

    /**
     * Call a [ScanTask] status method, degrading to "unavailable" if the Burp
     * implementation throws (some builds ship a stubbed `Crawl`).
     */
    private inline fun safe(name: String, block: () -> String): String = try {
        block()
    } catch (e: Throwable) {
        "unavailable"
    }

    private inline fun safeCount(name: String, block: () -> Int): String = try {
        block().toString()
    } catch (e: Throwable) {
        "unavailable"
    }
}
