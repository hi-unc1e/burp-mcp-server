package net.portswigger.mcp

import java.util.jar.Manifest

/**
 * Reads the extension's build metadata (version + build date) from the jar
 * Manifest so it can be surfaced in the Burp output log and the MCP serverInfo.
 *
 * This makes it trivial to tell which build of the extension is actually loaded
 * in a running Burp process — useful because Burp does not auto-reload an
 * extension whose jar file changed on disk unless it is manually reloaded.
 */
object ExtensionVersion {

    val version: String by lazy { readManifestAttribute("Implementation-Version") ?: "dev" }
    val buildDate: String by lazy { readManifestAttribute("Built-Date") ?: "unknown" }

    /**
     * One-line banner suitable for logging when the extension loads / the MCP
     * server starts, e.g.:
     *   Burp MCP Server v1.3.0-AT (built 2026-08-08T08:42:42Z)
     */
    val banner: String by lazy { "Burp MCP Server v$version (built $buildDate)" }

    private fun readManifestAttribute(name: String): String? = try {
        val resources = ExtensionVersion::class.java.classLoader.getResources("META-INF/MANIFEST.MF")
        // There are multiple manifests on the classpath (Burp's own, ktor, etc.);
        // pick the one whose Implementation-Title is our extension.
        for (url in resources) {
            url.openStream().use { input ->
                val manifest = Manifest(input)
                val attrs = manifest.mainAttributes
                val title = attrs.getValue("Implementation-Title")
                if (title == "burp-mcp") {
                    attrs.getValue(name)?.takeIf { it.isNotBlank() }?.let { return it }
                }
            }
        }
        null
    } catch (e: Throwable) {
        null
    }
}
