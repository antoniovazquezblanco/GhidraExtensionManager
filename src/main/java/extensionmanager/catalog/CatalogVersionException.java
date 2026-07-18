package extensionmanager.catalog;

/**
 * Thrown when the catalog on disk uses a format version this build of the
 * plugin does not know how to read.
 */
public class CatalogVersionException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public CatalogVersionException() {
		super("Unsupported catalog version. Please update the plugin.");
	}

	public CatalogVersionException(int version) {
		super("Unsupported catalog version " + version + ". Please update the plugin.");
	}
}
