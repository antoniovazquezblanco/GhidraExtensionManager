package extensionmanager.utils;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import ghidra.util.extensions.ExtensionDetails;

/**
 * Merges the different sources of extensions shown in the manager (locally
 * installed, bundled archives and the online catalog) into a single list with
 * one entry per extension.
 *
 * <p>{@link ExtensionDetails#equals(Object)} only matches within the same
 * concrete class, so an installed extension ({@link ExtensionDetails}) and its
 * catalog counterpart ({@link OnlineExtensionDetails}, a subclass) never compare
 * equal and would both appear as separate rows. This merges by extension
 * <em>name</em> instead, keeping the highest-priority source for each name:
 * installed &gt; archived &gt; online.
 */
public class ExtensionMerger {

	private ExtensionMerger() {
		// Utility class; not instantiable.
	}

	/**
	 * Merges the given extension sources into a single entry per extension name.
	 *
	 * @param installed locally installed extensions (highest priority)
	 * @param archived  bundled archive extensions
	 * @param online    catalog extensions (lowest priority)
	 * @return a set with one {@link ExtensionDetails} per name, preferring
	 *         installed over archived over online; iteration order is stable
	 *         (installed first, then archived, then online)
	 */
	public static Set<ExtensionDetails> merge(Set<? extends ExtensionDetails> installed,
			Set<? extends ExtensionDetails> archived, Set<? extends ExtensionDetails> online) {
		Map<String, ExtensionDetails> byName = new LinkedHashMap<>();
		addAllAbsent(byName, installed);
		addAllAbsent(byName, archived);
		addAllAbsent(byName, online);
		return new LinkedHashSet<>(byName.values());
	}

	private static void addAllAbsent(Map<String, ExtensionDetails> byName,
			Collection<? extends ExtensionDetails> extensions) {
		if (extensions == null) {
			return;
		}
		for (ExtensionDetails e : extensions) {
			byName.putIfAbsent(e.getName(), e);
		}
	}
}
