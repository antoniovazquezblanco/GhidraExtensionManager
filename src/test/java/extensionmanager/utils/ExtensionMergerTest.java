package extensionmanager.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.Test;

import ghidra.util.extensions.ExtensionDetails;

public class ExtensionMergerTest {

	private static ExtensionDetails installed(String name) {
		ExtensionDetails e = new ExtensionDetails(name, "desc", "author", "createdOn", "1.0");
		e.setInstallDir(new File("/tmp/installed/" + name));
		return e;
	}

	private static ExtensionDetails archived(String name) {
		ExtensionDetails e = new ExtensionDetails(name, "desc", "author", "createdOn", "1.0");
		e.setArchivePath("/tmp/archive/" + name + ".zip");
		return e;
	}

	private static OnlineExtensionDetails online(String name) throws Exception {
		return new OnlineExtensionDetails(name, "desc", "author", "createdOn", "1.0",
				"https://example.com/" + name + ".zip");
	}

	@SafeVarargs
	private static <T extends ExtensionDetails> Set<T> setOf(T... items) {
		return new LinkedHashSet<>(Arrays.asList(items));
	}

	private static Set<ExtensionDetails> none() {
		return new LinkedHashSet<>();
	}

	private static ExtensionDetails byName(Set<ExtensionDetails> set, String name) {
		return set.stream().filter(e -> name.equals(e.getName())).findFirst().orElse(null);
	}

	@Test
	public void onlineDuplicateOfInstalledCollapsesToInstalled() throws Exception {
		ExtensionDetails inst = installed("Foo");
		Set<ExtensionDetails> merged = ExtensionMerger.merge(setOf(inst), none(), setOf(online("Foo")));
		assertEquals(1, merged.size());
		assertSame("installed entry must win over the online duplicate", inst, byName(merged, "Foo"));
	}

	@Test
	public void onlineDuplicateOfArchivedCollapsesToArchived() throws Exception {
		ExtensionDetails arch = archived("Foo");
		Set<ExtensionDetails> merged = ExtensionMerger.merge(none(), setOf(arch), setOf(online("Foo")));
		assertEquals(1, merged.size());
		assertSame("archived entry must win over the online duplicate", arch, byName(merged, "Foo"));
	}

	@Test
	public void installedBeatsArchived() {
		ExtensionDetails inst = installed("Foo");
		Set<ExtensionDetails> merged = ExtensionMerger.merge(setOf(inst), setOf(archived("Foo")), none());
		assertEquals(1, merged.size());
		assertSame(inst, byName(merged, "Foo"));
	}

	@Test
	public void distinctExtensionsAreAllKept() throws Exception {
		Set<ExtensionDetails> merged =
			ExtensionMerger.merge(setOf(installed("A")), setOf(archived("B")), setOf(online("C")));
		assertEquals(3, merged.size());
		assertTrue(merged.stream().anyMatch(e -> e.getName().equals("A")));
		assertTrue(merged.stream().anyMatch(e -> e.getName().equals("B")));
		assertTrue(merged.stream().anyMatch(e -> e.getName().equals("C")));
	}

	@Test
	public void emptyInputsProduceEmptyResult() {
		assertTrue(ExtensionMerger.merge(none(), none(), none()).isEmpty());
	}
}
