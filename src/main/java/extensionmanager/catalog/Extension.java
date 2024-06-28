package extensionmanager.catalog;

import java.util.List;

public class Extension {
	public String name;
	public String description;
	public String author;
	public String created_on;
	List<ExtensionVersion> versions;
}
