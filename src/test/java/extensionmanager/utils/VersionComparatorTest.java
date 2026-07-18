package extensionmanager.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class VersionComparatorTest {

	private static int sign(int v) {
		return Integer.compare(v, 0);
	}

	@Test
	public void ordersNumericComponents() {
		assertTrue(VersionComparator.isNewer("1.2.3", "1.2.2"));
		assertFalse(VersionComparator.isNewer("1.2.2", "1.2.3"));
	}

	@Test
	public void equalVersionsAreNotNewer() {
		assertFalse(VersionComparator.isNewer("1.2.3", "1.2.3"));
		assertEquals(0, VersionComparator.INSTANCE.compare("1.2.3", "1.2.3"));
	}

	@Test
	public void missingTrailingComponentsAreZero() {
		assertEquals(0, VersionComparator.INSTANCE.compare("1.2", "1.2.0"));
		assertFalse(VersionComparator.isNewer("1.2", "1.2.0"));
		assertFalse(VersionComparator.isNewer("1.2.0", "1.2"));
	}

	@Test
	public void leadingVIsIgnored() {
		assertEquals(0, VersionComparator.INSTANCE.compare("v1.2.3", "1.2.3"));
		assertTrue(VersionComparator.isNewer("v2.0.0", "v1.9.9"));
	}

	@Test
	public void suffixAfterDashIsDropped() {
		assertEquals(0, VersionComparator.INSTANCE.compare("2.2.5-1-g40eb8e6", "2.2.5"));
		assertTrue(VersionComparator.isNewer("2.2.5-rc1", "2.2.4"));
	}

	@Test
	public void differentComponentCounts() {
		assertTrue(VersionComparator.isNewer("1.3", "1.2.9"));
		assertFalse(VersionComparator.isNewer("1.2.9", "1.3"));
	}

	@Test
	public void gitDescribeStyleSelfUpdateScenario() {
		// The generated GIT_VERSION looks like "v0.2.4-1-g40eb8e6"; a newer tag is "v0.2.5".
		assertTrue(VersionComparator.isNewer("v0.2.5", "v0.2.4-1-g40eb8e6"));
		// The current build is not "newer" than the tag it was built from.
		assertFalse(VersionComparator.isNewer("v0.2.4", "v0.2.4-1-g40eb8e6"));
	}

	@Test
	public void handlesNullEmptyAndNonNumericGracefully() {
		assertEquals(0, VersionComparator.INSTANCE.compare(null, ""));
		assertEquals(0, VersionComparator.INSTANCE.compare("", "0.0.0"));
		assertTrue(VersionComparator.isNewer("1.0", ""));
		// Non-numeric components parse as 0 instead of throwing.
		assertEquals(0, VersionComparator.INSTANCE.compare("1.x.3", "1.0.3"));
	}

	@Test
	public void comparisonIsAntisymmetric() {
		assertEquals(-sign(VersionComparator.INSTANCE.compare("1.2.3", "1.2.4")),
			sign(VersionComparator.INSTANCE.compare("1.2.4", "1.2.3")));
	}
}
