package extensionmanager.catalog.parser;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import extensionmanager.catalog.Catalog;

/**
 * Reads one specific catalog format version and maps it onto the
 * version-agnostic {@link Catalog} domain model.
 *
 * <p>To support a new catalog format, add an implementation and register it in
 * {@link #forVersion(int)}. Callers never pick a parser directly; they parse
 * through {@link Catalog#parse(java.io.Reader)}.
 */
public interface CatalogParser {

	/**
	 * Parses an already-tokenized catalog document.
	 *
	 * @param root the catalog JSON root object
	 * @param gson a configured Gson instance (catalog date format already set up)
	 * @return the normalized catalog
	 */
	Catalog parse(JsonObject root, Gson gson);

	/**
	 * @param version the catalog format version read from the {@code version} field
	 * @return a parser able to read that version, or {@code null} if the version is
	 *         not supported
	 */
	static CatalogParser forVersion(int version) {
		switch (version) {
			case 0:
				return new CatalogV0Parser();
			case 1:
				return new CatalogV1Parser();
			default:
				return null;
		}
	}
}
