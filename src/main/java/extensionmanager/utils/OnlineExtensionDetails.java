package extensionmanager.utils;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

import ghidra.util.extensions.ExtensionDetails;

public class OnlineExtensionDetails extends ExtensionDetails {

	/** The extension url */
	private URL url;

	/**
	 * Constructor.
	 * 
	 * @param name        unique name of the extension; cannot be null
	 * @param description brief explanation of what the extension does; can be null
	 * @param author      creator of the extension; can be null
	 * @param createdOn   creation date of the extension, can be null
	 * @param version     the extension version
	 * @param url         of the zip to install the extension from
	 * @throws URISyntaxException
	 * @throws MalformedURLException
	 */
	public OnlineExtensionDetails(String name, String description, String author, String createdOn, String version,
			String url) throws MalformedURLException, URISyntaxException {
		super(name, description, author, createdOn, version);
		this.url = new URI(url).toURL();
	}

	public URL getUrl() {
		return url;
	}
}
