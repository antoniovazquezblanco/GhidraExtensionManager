package extensionmanager.catalog;

/**
 * A single downloadable build of an {@link Extension}.
 *
 * <p>This is the version-agnostic representation used by the plugin. Regardless
 * of the on-disk catalog format that produced it, it always exposes the Ghidra
 * version the build targets, the (optional) extension release version, whether
 * the build comes from a prerelease and the URL to download it from.
 */
public class ExtensionVersion {
	private final String ghidraVersion;
	private final String extensionVersion;
	private final boolean prerelease;
	private final String url;
	private final String sha256;

	public ExtensionVersion(String ghidraVersion, String extensionVersion, boolean prerelease, String url,
			String sha256) {
		this.ghidraVersion = ghidraVersion;
		this.extensionVersion = extensionVersion;
		this.prerelease = prerelease;
		this.url = url;
		this.sha256 = sha256;
	}

	/**
	 * @return the Ghidra version this build targets (e.g. {@code "11.3.2"})
	 */
	public String getGhidraVersion() {
		return ghidraVersion;
	}

	/**
	 * @return the extension's own release version (e.g. {@code "2.2.5"}), or
	 *         {@code null} when the catalog format does not carry this information
	 */
	public String getExtensionVersion() {
		return extensionVersion;
	}

	/**
	 * @return {@code true} if this build comes from a prerelease
	 */
	public boolean isPrerelease() {
		return prerelease;
	}

	/**
	 * @return the download URL for this build, or {@code null} if none is available
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * @return the SHA-256 hex digest of this build's archive for integrity
	 *         verification, or {@code null} when the catalog format does not carry
	 *         it
	 */
	public String getSha256() {
		return sha256;
	}
}
