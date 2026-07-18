package extensionmanager.catalog;

import java.io.Reader;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import extensionmanager.catalog.parser.CatalogParser;

/**
 * In-memory, version-agnostic representation of the extension catalog.
 *
 * <p>The on-disk catalog format is versioned and expected to keep evolving. To
 * stay ahead of those changes the wire format is never exposed directly:
 * {@link #parse(Reader)} inspects the catalog {@code version} field, delegates
 * to the matching {@link CatalogParser} and returns this normalized model. The
 * rest of the plugin only ever deals with {@link Catalog}, {@link Extension}
 * and {@link ExtensionVersion}.
 */
public class Catalog {
	private final Date date;
	private final List<Extension> extensions;

	public Catalog(Date date, List<Extension> extensions) {
		this.date = date;
		this.extensions = extensions == null ? Collections.emptyList() : List.copyOf(extensions);
	}

	/**
	 * @return the date the catalog was generated, or {@code null} if unknown
	 */
	public Date getDate() {
		return date;
	}

	/**
	 * @return every extension in the catalog (never {@code null})
	 */
	public List<Extension> getExtensions() {
		return extensions;
	}

	/**
	 * Parses a catalog from the given reader, selecting the reader implementation
	 * that matches the catalog format version.
	 *
	 * @param reader the catalog JSON source
	 * @return the parsed, normalized catalog
	 * @throws CatalogVersionException if the catalog format version is missing or
	 *                                 not supported by this version of the plugin
	 */
	public static Catalog parse(Reader reader) throws CatalogVersionException {
		Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.S").create();
		JsonObject root = JsonParser.parseReader(reader).getAsJsonObject();
		if (!root.has("version") || !root.get("version").isJsonPrimitive())
			throw new CatalogVersionException();
		int version = root.get("version").getAsInt();
		CatalogParser parser = CatalogParser.forVersion(version);
		if (parser == null)
			throw new CatalogVersionException(version);
		return parser.parse(root, gson);
	}
}
