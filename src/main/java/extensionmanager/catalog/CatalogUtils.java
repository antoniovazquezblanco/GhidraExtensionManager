package extensionmanager.catalog;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import extensionmanager.utils.OnlineExtensionDetails;
import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class CatalogUtils {
	private static final Logger log = LogManager.getLogger(CatalogUtils.class);

	private static Catalog catalog;

	private static File getCatalogFile() {
		try {
			ResourceFile resourceFile = Application.getModuleDataFile("catalog.json");
			return resourceFile.getFile(true);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error(e);
		}
		return null;
	}

	public static boolean update() {
		log.trace("Updating catalog...");
		try {
			File file = getCatalogFile();
			URL url = new URI(
					"https://github.com/antoniovazquezblanco/GhidraExtensionManagerRepository/releases/download/latest/catalog.json")
					.toURL();
			FileUtils.copyURLToFile(url, file);
			// Force reload of catalog after update
			loadCatalog();
			return true;
		} catch (MalformedURLException | URISyntaxException e) {
			log.error(e);
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			log.error(e);
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private static void loadCatalog() {
		log.trace("Loading extension catalog...");
		try {
			File catalog_file = getCatalogFile();
			Reader reader = Files.newBufferedReader(catalog_file.toPath());
			catalog = Catalog.parse(reader);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error(e);
		}
	}

	public static Date getCatalogDate() {
		if (catalog == null)
			loadCatalog();
		return catalog.date;
	}

	public static Set<OnlineExtensionDetails> getExtensions(String ghidraVersion) {
		if (catalog == null)
			loadCatalog();
		Set<OnlineExtensionDetails> extensions = new HashSet<OnlineExtensionDetails>();
		for (Extension e : catalog.extensions) {
			for (ExtensionVersion v : e.versions) {
				if (v.version.equals(ghidraVersion)) {
					try {
						extensions.add(new OnlineExtensionDetails(e.name, e.description, e.author, e.created_on,
								v.version, v.url));
					} catch (MalformedURLException | URISyntaxException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
						log.error(e1);
					}
				}
			}
		}
		return extensions;
	}

	public static Set<OnlineExtensionDetails> getCurrentVersionExtensions() {
		String ghidraVersion = Application.getApplicationVersion();
		return getExtensions(ghidraVersion);
	}
}
