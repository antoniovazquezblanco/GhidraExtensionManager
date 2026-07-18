package extensionmanager.utils;

import java.util.Comparator;

/**
 * Compares dotted numeric version strings such as {@code "1.2.3"} or
 * {@code "v2.2.5-1-g40eb8e6"}.
 *
 * <p>Parsing rules:
 * <ul>
 * <li>a single leading {@code v}/{@code V} is ignored;</li>
 * <li>everything from the first {@code -} onwards (pre-release / build metadata)
 * is dropped;</li>
 * <li>the remaining dot-separated numeric components are compared left to right,
 * with missing trailing components treated as {@code 0};</li>
 * <li>non-numeric or absent components parse as {@code 0} rather than failing.</li>
 * </ul>
 *
 * So {@code "1.2"} equals {@code "1.2.0"}, and {@code "2.2.5-rc1"} equals
 * {@code "2.2.5"}. Reusable for both the plugin self-update check and extension
 * update detection.
 */
public class VersionComparator implements Comparator<String> {

	/** Shared stateless instance. */
	public static final VersionComparator INSTANCE = new VersionComparator();

	@Override
	public int compare(String a, String b) {
		int[] pa = parse(a);
		int[] pb = parse(b);
		int n = Math.max(pa.length, pb.length);
		for (int i = 0; i < n; i++) {
			int x = i < pa.length ? pa[i] : 0;
			int y = i < pb.length ? pb[i] : 0;
			if (x != y) {
				return Integer.compare(x, y);
			}
		}
		return 0;
	}

	/**
	 * @param candidate the version to test
	 * @param base      the version to compare against
	 * @return {@code true} if {@code candidate} is strictly newer than {@code base}
	 */
	public static boolean isNewer(String candidate, String base) {
		return INSTANCE.compare(candidate, base) > 0;
	}

	private static int[] parse(String version) {
		String v = version == null ? "" : version.trim();
		if (v.startsWith("v") || v.startsWith("V")) {
			v = v.substring(1);
		}
		int dash = v.indexOf('-');
		if (dash >= 0) {
			v = v.substring(0, dash);
		}
		if (v.isEmpty()) {
			return new int[0];
		}
		String[] parts = v.split("\\.");
		int[] out = new int[parts.length];
		for (int i = 0; i < parts.length; i++) {
			out[i] = parseComponent(parts[i]);
		}
		return out;
	}

	private static int parseComponent(String part) {
		try {
			return Integer.parseInt(part.trim());
		} catch (NumberFormatException e) {
			return 0;
		}
	}
}
