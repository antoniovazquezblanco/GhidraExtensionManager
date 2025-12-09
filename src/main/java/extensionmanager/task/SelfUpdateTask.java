package extensionmanager.task;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.kohsuke.github.GHAsset;
import org.kohsuke.github.GHRelease;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;

import docking.widgets.OptionDialog;
import extensionmanager.ExtensionManagerVersion;
import extensionmanager.utils.OnlineExtensionInstaller;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class SelfUpdateTask extends Task {

	private static final Logger log = LogManager.getLogger(SelfUpdateTask.class);
	private static final String REPO_OWNER = "antoniovazquezblanco";
	private static final String REPO_NAME = "GhidraExtensionManager";

	public static class VersionInfo {
		private final String version;
		private final URL url;

		public VersionInfo(String version, URL url) {
			this.version = version;
			this.url = url;
		}

		public String getVersion() {
			return version;
		}

		public URL getUrl() {
			return url;
		}
	}

	public SelfUpdateTask() {
		super("Extension Manager self update task", false, true, true);
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Updating extension manager...");
		VersionInfo latestVersion = getLatestPluginInfo(monitor);
		if (latestVersion == null) {
			log.warn("Could not retrieve latest version info.");
			return;
		}

		log.info(String.format("Got extension manager version info: %s", latestVersion.getVersion()));
		if (!isNewerVersion(latestVersion.getVersion(), ExtensionManagerVersion.GIT_VERSION)) {
			log.info("Extension Manager is up to date.");
			return;
		}

		boolean update = askYesNo("Extension Manager Update", "Would you like to update now?");
		if (!update) {
			log.info("User declined update...");
			return;
		}

		log.info("Installing update...");
		boolean success = OnlineExtensionInstaller.install(latestVersion.getUrl());
		if (success) {
			Msg.showInfo(getClass(), null, "Extension Manager Update",
					"Update installed successfully. Please restart Ghidra to apply the changes.");
		} else {
			Msg.showError(getClass(), null, "Extension Manager Update", "Failed to install update.");
		}
	}
	
	public boolean askYesNo(String title, String question) {
		return OptionDialog.showYesNoDialog(null, title, question) == OptionDialog.OPTION_ONE;
	}

	private static boolean isNewerVersion(String latest, String current) {
		String latestVer = latest.startsWith("v") ? latest.substring(1) : latest;
		String currentVer = current.startsWith("v") ? current.substring(1) : current;
		// Take only the version part before any dash
		latestVer = latestVer.split("-")[0];
		currentVer = currentVer.split("-")[0];
		String[] latestParts = latestVer.split("\\.");
		String[] currentParts = currentVer.split("\\.");
		for (int i = 0; i < Math.max(latestParts.length, currentParts.length); i++) {
			int l = i < latestParts.length ? Integer.parseInt(latestParts[i]) : 0;
			int c = i < currentParts.length ? Integer.parseInt(currentParts[i]) : 0;
			if (l > c)
				return true;
			if (l < c)
				return false;
		}
		return false; // equal
	}

	private static VersionInfo getLatestPluginInfo(TaskMonitor monitor) throws CancelledException {
		String ghidraVersion = Application.getApplicationVersion();
		monitor.checkCancelled();
		return getLatestPluginInfo(monitor, ghidraVersion);
	}

	/**
	 * Retrieves the version and download URL of the latest GhidraExtensionManager
	 * plugin compatible with the specified Ghidra version.
	 *
	 * @param ghidraVersion the Ghidra version (e.g., "11.2.1")
	 * @return the PluginInfo containing version and URL of the latest compatible
	 *         plugin, or null if not found
	 */
	private static VersionInfo getLatestPluginInfo(TaskMonitor monitor, String ghidraVersion) throws CancelledException {
		monitor.checkCancelled();
		try {
			GitHub github = GitHub.connectAnonymously();
			monitor.checkCancelled();
			GHRepository repo = github.getRepository(REPO_OWNER + "/" + REPO_NAME);
			monitor.checkCancelled();
			List<GHRelease> releases = repo.listReleases().toList();
			monitor.checkCancelled();

			// Find the latest release that has an asset for the given Ghidra version
			Optional<GHRelease> latestRelease = releases.stream()
					.filter(release -> !release.isDraft() && !release.isPrerelease())
					.filter(release -> hasAssetForVersion(monitor, release, ghidraVersion))
					.max(Comparator.comparing(GHRelease::getPublished_at));
			monitor.checkCancelled();

			if (latestRelease.isPresent()) {
				GHAsset asset = findAssetForVersion(monitor, latestRelease.get(), ghidraVersion);
				monitor.checkCancelled();
				if (asset != null) {
					return new VersionInfo(latestRelease.get().getTagName(),
							new URI(asset.getBrowserDownloadUrl()).toURL());
				}
			}

			return null;
		} catch (IOException | URISyntaxException e) {
			log.error("Failed to get latest plugin info", e);
			return null;
		}
	}

	/**
	 * Checks if a release has an asset for the specified Ghidra version.
	 * @throws CancelledException 
	 */
	private static boolean hasAssetForVersion(TaskMonitor monitor, GHRelease release, String ghidraVersion) {
		if (monitor.isCancelled())
			return false;
		try {
			return release.listAssets().toList().stream()
					.anyMatch(asset -> asset.getName().contains("ghidra_" + ghidraVersion + "_PUBLIC"));
		} catch (IOException e) {
			log.error("Failed to list assets for release " + release.getTagName(), e);
			return false;
		}
	}

	/**
	 * Finds the asset for the specified Ghidra version in a release.
	 * @throws CancelledException 
	 */
	private static GHAsset findAssetForVersion(TaskMonitor monitor, GHRelease release, String ghidraVersion) throws CancelledException {
		monitor.checkCancelled();
		try {
			List<GHAsset> assets = release.listAssets().toList();
			monitor.checkCancelled();
			return assets.stream().filter(asset -> asset.getName().contains("ghidra_" + ghidraVersion + "_PUBLIC"))
					.findFirst().orElse(null);
		} catch (IOException e) {
			log.error("Failed to list assets for release " + release.getTagName(), e);
			return null;
		}
	}
}
