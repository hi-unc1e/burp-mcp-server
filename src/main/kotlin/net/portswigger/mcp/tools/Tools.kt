package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    // ── P0: Scope / Sitemap / Scanner lifecycle ──────────────────────────

    mcpTool<IncludeInScope>("Adds a URL prefix to Burp suite-wide target scope.") {
        api.scope().includeInScope(url)
        api.logging().logToOutput("MCP include in scope: $url")
        "Included in scope: $url"
    }

    mcpTool<ExcludeFromScope>("Removes a URL prefix from Burp suite-wide target scope.") {
        api.scope().excludeFromScope(url)
        api.logging().logToOutput("MCP exclude from scope: $url")
        "Excluded from scope: $url"
    }

    mcpTool<IsInScope>("Checks whether a URL is inside the current suite-wide target scope.") {
        val inScope = api.scope().isInScope(url)
        "url: $url\ninScope: $inScope"
    }

    mcpPaginatedTool<ListSitemap>(
        "Lists Site Map HTTP request/response pairs. Optional urlPrefix filters by path prefix (SiteMapFilter.prefixFilter)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "sitemap")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Sitemap access denied by Burp Suite")
        }

        val items = if (urlPrefix.isNullOrBlank()) {
            api.siteMap().requestResponses()
        } else {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix))
        }

        items.asSequence().map { rr ->
            truncateIfNeeded(
                buildString {
                    appendLine("url: ${rr.url()}")
                    appendLine("status: ${if (rr.hasResponse()) rr.statusCode() else "n/a"}")
                    appendLine("method: ${rr.request().method()}")
                    appendLine("request:")
                    append(rr.request().toString().take(2000))
                    if (rr.hasResponse()) {
                        appendLine()
                        appendLine("response:")
                        append(rr.response().toString().take(2000))
                    }
                }
            )
        }
    }

    mcpPaginatedTool<GetScannerIssuesForUrl>(
        "Lists scanner issues whose base URL matches the given URL prefix filter."
    ) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            return@mcpPaginatedTool sequenceOf("Scanner issues require Burp Suite Professional")
        }

        val issues = if (urlPrefix.isNullOrBlank()) {
            api.siteMap().issues()
        } else {
            api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
        }

        issues.asSequence().map { Json.encodeToString(it.toSerializableForm()) }
    }

    mcpTool<StartCrawl>(
        "Starts a Burp crawler against one or more seed URLs (Professional). Returns a taskId for list/status/delete."
    ) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            return@mcpTool "Crawl requires Burp Suite Professional"
        }
        if (seedUrls.isEmpty()) {
            return@mcpTool "Error: seedUrls must not be empty"
        }

        val crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray()))
        val entry = ScanTaskRegistry.register(
            kind = "crawl",
            label = seedUrls.joinToString(","),
            task = crawl,
        )
        api.logging().logToOutput("MCP start crawl taskId=${entry.id} seeds=$seedUrls")
        "Started crawl\n" + ScanTaskRegistry.snapshot(entry)
    }

    mcpTool<StartAudit>(
        "Starts a Burp audit (Professional). mode: LEGACY_PASSIVE_AUDIT_CHECKS or LEGACY_ACTIVE_AUDIT_CHECKS. " +
            "Optional rawHttpRequest + target* fields enqueue a single request for audit."
    ) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            return@mcpTool "Audit requires Burp Suite Professional"
        }

        val builtIn = when (mode.uppercase()) {
            "LEGACY_ACTIVE_AUDIT_CHECKS", "ACTIVE" -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            else -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
        }

        val audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(builtIn))

        if (!rawHttpRequest.isNullOrBlank() && !targetHostname.isNullOrBlank() && targetPort != null && usesHttps != null) {
            val fixed = normalizeHttpContent(rawHttpRequest)
            val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
            val request = HttpRequest.httpRequest(service, fixed)
            audit.addRequest(request)
        }

        val entry = ScanTaskRegistry.register(
            kind = "audit",
            label = mode,
            task = audit,
        )
        api.logging().logToOutput("MCP start audit taskId=${entry.id} mode=$mode")
        "Started audit\n" + ScanTaskRegistry.snapshot(entry)
    }

    mcpTool("list_scan_tasks", "Lists scanner tasks started via MCP (crawl/audit) with status and counts.") {
        val entries = ScanTaskRegistry.list()
        if (entries.isEmpty()) {
            "No MCP-started scan tasks"
        } else {
            entries.joinToString("\n\n") { ScanTaskRegistry.snapshot(it) }
        }
    }

    mcpTool<GetScanTaskStatus>("Returns status for a scan task previously started via MCP.") {
        val entry = ScanTaskRegistry.get(taskId)
            ?: return@mcpTool "Unknown taskId: $taskId"
        ScanTaskRegistry.snapshot(entry)
    }

    mcpTool<DeleteScanTask>("Deletes a scan task previously started via MCP (also removes it from Burp's task list).") {
        val entry = ScanTaskRegistry.remove(taskId)
            ?: return@mcpTool "Unknown taskId: $taskId"
        entry.task.delete()
        "Deleted scan task $taskId (${entry.kind})"
    }

    // ── P1: Inspect / bulk send ─────────────────────────────────────────

    mcpTool<InspectProxyHttpHistoryItem>(
        "Returns one Proxy HTTP history item by zero-based index (after optional regex filter on request/response text)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = if (regex.isNullOrBlank()) {
            api.proxy().history()
        } else {
            val compiled = Pattern.compile(regex)
            api.proxy().history { it.contains(compiled) }
        }

        if (index < 0 || index >= history.size) {
            return@mcpTool "Index $index out of range (size=${history.size})"
        }

        val item = history[index]
        truncateIfNeeded(Json.encodeToString(item.toSerializableForm()))
    }

    mcpTool<BulkSendHttp1Requests>(
        "Sends multiple HTTP/1.1 requests sequentially and returns a short status per item. " +
            "Each item needs content + targetHostname/targetPort/usesHttps. Honors HTTP request approval settings."
    ) {
        if (requests.isEmpty()) {
            return@mcpTool "Error: requests must not be empty"
        }

        val lines = mutableListOf<String>()
        requests.forEachIndexed { i, req ->
            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(
                    req.targetHostname, req.targetPort, config, req.content, api
                )
            }
            if (!allowed) {
                lines += "[$i] DENIED ${req.targetHostname}:${req.targetPort}"
                return@forEachIndexed
            }
            val fixed = normalizeHttpContent(req.content)
            val request = HttpRequest.httpRequest(req.toMontoyaService(), fixed)
            val rr = api.http().sendRequest(request)
            val status = if (rr != null && rr.hasResponse()) rr.statusCode().toString() else "n/a"
            // Prefer toByteArray() (same as compare tool) — body() can fail resolution under compileOnly Montoya interop.
            val len = rr?.response()?.toByteArray()?.length() ?: 0
            lines += "[$i] HTTP $status bodyLen=$len host=${req.targetHostname}:${req.targetPort}"
        }
        lines.joinToString("\n")
    }

    mcpTool<CompareProxyHistoryItems>(
        "Compares two Proxy history items by index (method/url/status/length + simple request/response digests)."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpTool "HTTP history access denied by Burp Suite"
        }

        val history = api.proxy().history()
        if (indexA !in history.indices || indexB !in history.indices) {
            return@mcpTool "Index out of range (size=${history.size})"
        }
        val a = history[indexA]
        val b = history[indexB]
        fun summarize(label: String, item: burp.api.montoya.proxy.ProxyHttpRequestResponse): String {
            val req = item.finalRequest()
            val resp = item.response()
            return buildString {
                appendLine("$label:")
                appendLine("  ${req.method()} ${req.url()}")
                appendLine("  status=${resp?.statusCode() ?: "n/a"} reqLen=${req.toByteArray().length()} respLen=${resp?.toByteArray()?.length() ?: 0}")
            }
        }
        summarize("A[$indexA]", a) + summarize("B[$indexB]", b) +
            "sameMethod=${a.finalRequest().method() == b.finalRequest().method()}\n" +
            "sameUrl=${a.finalRequest().url() == b.finalRequest().url()}"
    }

    // ── P2: Sitemap inject + BCheck import ──────────────────────────────

    mcpTool<AddToSitemap>(
        "Adds a request (and optional response) to the Site Map. Useful after OpenAPI/manual discovery when no dedicated OpenAPI Montoya API is available."
    ) {
        val fixed = normalizeHttpContent(content)
        val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
        val request = HttpRequest.httpRequest(service, fixed)
        val rr = if (responseContent.isNullOrBlank()) {
            burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                request,
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse()
            )
        } else {
            burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                request,
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(responseContent)
            )
        }
        api.siteMap().add(rr)
        "Added to sitemap: ${request.method()} ${request.url()}"
    }

    mcpTool<ImportBCheck>(
        "Imports a BCheck script into Burp Scanner (Professional). Pass the full BCheck source. " +
            "This is the supported Montoya path for custom scan checks; arbitrary ActiveScanCheck classes are not loadable via one-shot MCP."
    ) {
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
            return@mcpTool "BCheck import requires Burp Suite Professional"
        }
        val result = if (overwriteExisting) {
            api.scanner().bChecks().importBCheck(script, true)
        } else {
            api.scanner().bChecks().importBCheck(script)
        }
        buildString {
            appendLine("status: ${result.status()}")
            val errors = result.importErrors()
            if (errors.isNotEmpty()) {
                appendLine("errors:")
                errors.forEach { appendLine("  - $it") }
            } else {
                appendLine("errors: (none)")
            }
        }.trimEnd()
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

// ── P0 / P1 / P2 parameter types ────────────────────────────────────────

@Serializable
data class IncludeInScope(val url: String)

@Serializable
data class ExcludeFromScope(val url: String)

@Serializable
data class IsInScope(val url: String)

@Serializable
data class ListSitemap(
    val urlPrefix: String? = null,
    override val count: Int,
    override val offset: Int,
) : Paginated

@Serializable
data class GetScannerIssuesForUrl(
    val urlPrefix: String? = null,
    override val count: Int,
    override val offset: Int,
) : Paginated

@Serializable
data class StartCrawl(
    val seedUrls: List<String>,
)

@Serializable
data class StartAudit(
    val mode: String = "LEGACY_PASSIVE_AUDIT_CHECKS",
    val rawHttpRequest: String? = null,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
)

@Serializable
data class GetScanTaskStatus(val taskId: String)

@Serializable
data class DeleteScanTask(val taskId: String)

@Serializable
data class InspectProxyHttpHistoryItem(
    val index: Int,
    val regex: String? = null,
)

@Serializable
data class BulkSendHttp1Item(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class BulkSendHttp1Requests(
    val requests: List<BulkSendHttp1Item>,
)

@Serializable
data class CompareProxyHistoryItems(
    val indexA: Int,
    val indexB: Int,
)

@Serializable
data class AddToSitemap(
    val content: String,
    val responseContent: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class ImportBCheck(
    val script: String,
    val overwriteExisting: Boolean = false,
)
