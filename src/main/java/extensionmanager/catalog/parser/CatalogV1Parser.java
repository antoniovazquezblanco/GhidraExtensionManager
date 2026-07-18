package extensionmanager.catalog.parser;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import extensionmanager.catalog.Catalog;
import extensionmanager.catalog.Extension;
import extensionmanager.catalog.ExtensionVersion;

/**
 * Reader for catalog format version 1.
 *
 * <p>In v1 each entry under an extension is a single, self-contained installable
 * build: it carries both the extension's own release ({@code extension_version})
 * and the Ghidra version it targets ({@code ghidra_version}), plus the
 * prerelease flag, the download {@code url} and an optional {@code sha256}. The
 * extension itself also carries a {@code repository} URL. This maps one-to-one
 * onto the plugin's flat domain model.
 *
 * <pre>
 * { "version": 1, "date": "...", "extensions": [
 *     { "name": "...", "description": "...", "author": "...", "created_on": "...",
 *       "repository": "https://...",
 *       "versions": [
 *         { "extension_version": "v2.2.5", "ghidra_version": "11.4",
 *           "is_prerelease": false, "url": "https://...", "sha256": "..." } ] } ] }
 * </pre>
 */
public class CatalogV1Parser implements CatalogParser {

	private static class RawCatalog {
		Date date;
		List<RawExtension> extensions;
	}

	private static class RawExtension {
		String name;
		String description;
		String author;
		String created_on;
		String repository;
		List<RawVersion> versions;
	}

	private static class RawVersion {
		String extension_version;
		String ghidra_version;
		Boolean is_prerelease;
		String url;
		String sha256;
	}

	@Override
	public Catalog parse(JsonObject root, Gson gson) {
		RawCatalog raw = gson.fromJson(root, RawCatalog.class);
		List<Extension> extensions = new ArrayList<>();
		if (raw.extensions != null) {
			for (RawExtension e : raw.extensions) {
				List<ExtensionVersion> versions = new ArrayList<>();
				if (e.versions != null) {
					for (RawVersion v : e.versions) {
						versions.add(new ExtensionVersion(v.ghidra_version, v.extension_version,
								Boolean.TRUE.equals(v.is_prerelease), v.url, v.sha256));
					}
				}
				extensions.add(new Extension(e.name, e.description, e.author, e.created_on, e.repository, versions));
			}
		}
		return new Catalog(raw.date, extensions);
	}
}
