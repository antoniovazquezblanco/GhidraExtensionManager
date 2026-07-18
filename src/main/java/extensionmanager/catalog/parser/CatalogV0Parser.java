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
 * Reader for catalog format version 0.
 *
 * <p>In v0 each version entry stores the targeted Ghidra version in a field
 * literally named {@code version} together with a single download {@code url}.
 * There is no notion of an extension release version or of prereleases.
 *
 * <pre>
 * { "version": 0, "date": "...", "extensions": [
 *     { "name": "...", "description": "...", "author": "...", "created_on": "...",
 *       "versions": [ { "version": "11.3.2", "url": "https://..." } ] } ] }
 * </pre>
 */
public class CatalogV0Parser implements CatalogParser {

	private static class RawCatalog {
		Date date;
		List<RawExtension> extensions;
	}

	private static class RawExtension {
		String name;
		String description;
		String author;
		String created_on;
		List<RawVersion> versions;
	}

	private static class RawVersion {
		String version; // holds the Ghidra version in v0
		String url;
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
						versions.add(new ExtensionVersion(v.version, null, false, v.url, null));
					}
				}
				extensions.add(new Extension(e.name, e.description, e.author, e.created_on, null, versions));
			}
		}
		return new Catalog(raw.date, extensions);
	}
}
