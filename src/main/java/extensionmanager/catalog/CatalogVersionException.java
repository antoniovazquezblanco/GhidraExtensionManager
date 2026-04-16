package extensionmanager.catalog;

public class CatalogVersionException extends RuntimeException {
	public CatalogVersionException() {
		super("Unsupported catalog version. Please update the plugin.");
	}
}
