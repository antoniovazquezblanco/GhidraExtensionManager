package extensionmanager.utils;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.project.extensions.ExtensionInstaller;

public class OnlineExtensionInstaller extends ExtensionInstaller {
	private static final Logger log = LogManager.getLogger(OnlineExtensionInstaller.class);

	/**
	 * Installs the given extension from a resource URL. The URL should point to an
	 * archive (zip) that contains an extension.properties file.
	 *
	 * @param url of the extension to install
	 * @return true if the extension was successfully installed
	 */
	public static boolean install(URL url) {
		log.trace("Installing extension from url " + url);

		if (url == null) {
			log.error("Install url cannot be null");
			return false;
		}

		try {
			File file = File.createTempFile("GhidraExtension", ".zip");
			file.deleteOnExit();
			FileUtils.copyURLToFile(url, file);
			return install(file);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	/**
	 * Installs the given extension.
	 *
	 * @param url of the extension to install
	 * @return true if the extension was successfully installed
	 */
	public static boolean install(OnlineExtensionDetails details) {
		URL url = details.getUrl();
		return install(url);
	}
}
