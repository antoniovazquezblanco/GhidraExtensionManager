package extensionmanager.catalog;

import java.util.Collections;
import java.util.List;

/**
 * A catalog extension together with all of its downloadable versions.
 *
 * <p>Version-agnostic: the parser layer maps every supported catalog format
 * into this shape so the rest of the plugin never needs to care about the
 * on-disk schema.
 */
public class Extension {
	private final String name;
	private final String description;
	private final String author;
	private final String createdOn;
	private final String repository;
	private final List<ExtensionVersion> versions;

	public Extension(String name, String description, String author, String createdOn, String repository,
			List<ExtensionVersion> versions) {
		this.name = name;
		this.description = description;
		this.author = author;
		this.createdOn = createdOn;
		this.repository = repository;
		this.versions = versions == null ? Collections.emptyList() : List.copyOf(versions);
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getAuthor() {
		return author;
	}

	public String getCreatedOn() {
		return createdOn;
	}

	/**
	 * @return the extension's source/home repository URL, or {@code null} when the
	 *         catalog format does not carry this information
	 */
	public String getRepository() {
		return repository;
	}

	/**
	 * @return every known build of this extension (never {@code null})
	 */
	public List<ExtensionVersion> getVersions() {
		return versions;
	}
}
