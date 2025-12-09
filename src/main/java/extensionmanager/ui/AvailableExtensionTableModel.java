package extensionmanager.ui;

import java.awt.Component;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import extensionmanager.catalog.CatalogUtils;
import extensionmanager.utils.OnlineExtensionDetails;
import extensionmanager.utils.OnlineExtensionInstaller;
import generic.jar.ResourceFile;
import ghidra.docking.settings.Settings;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.project.extensions.ExtensionInstaller;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

class AvailableExtensionTableModel extends ThreadedTableModel<ExtensionDetails, Object> {

	private static final long serialVersionUID = 7081260710920183727L;
	final static int INSTALLED_COL = 0;
	final static int NAME_COL = 1;

	private Set<ExtensionDetails> extensions;
	private Map<String, Boolean> originalInstallStates = new HashMap<>();

	protected AvailableExtensionTableModel(ServiceProvider serviceProvider) {
		super("Extensions", serviceProvider);
	}

	@Override
	protected TableColumnDescriptor<ExtensionDetails> createTableColumnDescriptor() {
		TableColumnDescriptor<ExtensionDetails> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new ExtensionInstalledColumn(), INSTALLED_COL, true);
		descriptor.addVisibleColumn(new ExtensionNameColumn(), NAME_COL, true);
		descriptor.addVisibleColumn(new ExtensionDescriptionColumn());
		descriptor.addVisibleColumn(new ExtensionVersionColumn());
		descriptor.addHiddenColumn(new ExtensionInstallationDirColumn());
		descriptor.addHiddenColumn(new ExtensionArchiveFileColumn());
		return descriptor;
	}

	@Override
	public int getPrimarySortColumnIndex() {
		return NAME_COL;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (Application.inSingleJarMode()) {
			return false;
		}
		ExtensionDetails extension = getSelectedExtension(rowIndex);
		if (extension.isInstalledInInstallationFolder()) {
			return false;
		}
		return columnIndex == INSTALLED_COL;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		if (columnIndex != INSTALLED_COL) {
			return;
		}
		ResourceFile installDir = Application.getApplicationLayout().getExtensionInstallationDirs().get(0);
		if (!installDir.exists() && !installDir.mkdir()) {
			Msg.showError(this, null, "Directory Error",
					"Cannot install/uninstall extensions: Failed to create extension installation "
							+ "directory.\nSee the \"Ghidra Extension Notes\" section of the Ghidra "
							+ "Installation Guide for more information.");
		}
		if (!installDir.canWrite()) {
			Msg.showError(this, null, "Permissions Error",
					"Cannot install/uninstall extensions: Invalid write permissions on installation "
							+ "directory.\nSee the \"Ghidra Extension Notes\" section of the Ghidra "
							+ "Installation Guide for more information.");
			return;
		}

		boolean install = ((Boolean) aValue).booleanValue();
		ExtensionDetails extension = getSelectedExtension(rowIndex);
		if (!install) {
			if (extension.markForUninstall()) {
				refreshTable();
			}
			return;
		}
		if (extension.isPendingUninstall()) {
			if (extension.clearMarkForUninstall()) {
				refreshTable();
				return;
			}
		}

		if (extension.isFromArchive()) {
			if (ExtensionInstaller.installExtensionFromArchive(extension)) {
				refreshTable();
			}
			return;
		} else if (extension.getClass().equals(OnlineExtensionDetails.class)) {
			if (OnlineExtensionInstaller.install((OnlineExtensionDetails) extension)) {
				refreshTable();
			}
			return;
		}

		// This is a programming error
		Msg.error(this, "Unable install an extension that no longer exists. Restart Ghidra and "
				+ "try manually installing the extension: '" + extension.getName() + "'");
	}

	private boolean matchesGhidraVersion(ExtensionDetails details) {
		String ghidraVersion = Application.getApplicationVersion();
		String extensionVersion = details.getVersion();
		return ghidraVersion.equals(extensionVersion);
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	@Override
	protected void doLoad(Accumulator<ExtensionDetails> accumulator, TaskMonitor monitor) throws CancelledException {
		if (extensions != null) {
			accumulator.addAll(extensions);
			return;
		}

		ExtensionUtils.reload();
		Set<ExtensionDetails> archived = ExtensionUtils.getArchiveExtensions();
		Set<ExtensionDetails> installed = ExtensionUtils.getInstalledExtensions();
		Set<OnlineExtensionDetails> online = CatalogUtils.getCurrentVersionExtensions();

		// don't show archived extensions that have been installed
		for (ExtensionDetails extension : installed) {
			if (archived.remove(extension)) {
				Msg.trace(this, "Not showing archived extension that has been installed.  Archive path: "
						+ extension.getArchivePath()); // useful for debugging
			}
		}

		extensions = new HashSet<>();
		extensions.addAll(installed);
		extensions.addAll(archived);
		extensions.addAll(online);

		for (ExtensionDetails e : extensions) {
			String name = e.getName();
			if (originalInstallStates.containsKey(name)) {
				continue; // preserve the original value
			}
			originalInstallStates.put(e.getName(), e.isInstalled());
		}

		accumulator.addAll(extensions);
	}

	public boolean hasModelChanged() {

		for (ExtensionDetails e : extensions) {
			Boolean wasInstalled = originalInstallStates.get(e.getName());
			if (e.isInstalled() != wasInstalled) {
				return true;
			}
		}

		return false;
	}

	public void setModelData(List<ExtensionDetails> model) {
		extensions = new HashSet<>(model);
		reload();
	}

	public void refreshTable() {
		extensions = null;
		reload();
	}

	private ExtensionDetails getSelectedExtension(int row) {
		return getRowObject(row);
	}

	private class ExtensionNameColumn extends AbstractDynamicTableColumn<ExtensionDetails, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getName();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class ExtensionDescriptionColumn extends AbstractDynamicTableColumn<ExtensionDetails, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getDescription();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class ExtensionVersionColumn extends AbstractDynamicTableColumn<ExtensionDetails, String, Object> {

		private ExtRenderer renderer = new ExtRenderer();

		@Override
		public String getColumnName() {
			return "Version";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {

			String version = rowObject.getVersion();

			// Check for the default version value. If this is still set, then no version
			// has been
			// established so just display an empty string.
			if (version == null || version.equals("@extversion@")) {
				return "";
			}

			return version;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class ExtensionInstalledColumn extends AbstractDynamicTableColumn<ExtensionDetails, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Installation Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Boolean getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.isInstalled();
		}
	}

	private class ExtensionInstallationDirColumn extends AbstractDynamicTableColumn<ExtensionDetails, String, Object> {

		@Override
		public String getColumnName() {
			return "Installation Directory";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getInstallPath();
		}
	}

	private class ExtensionArchiveFileColumn extends AbstractDynamicTableColumn<ExtensionDetails, String, Object> {

		@Override
		public String getColumnName() {
			return "Archive File";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(ExtensionDetails rowObject, Settings settings, Object data, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getArchivePath();
		}
	}

	private class ExtRenderer extends AbstractGColumnRenderer<String> {

		private static final long serialVersionUID = -3317456845964697608L;

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component comp = super.getTableCellRendererComponent(data);

			ExtensionDetails extension = getSelectedExtension(data.getRowViewIndex());
			if (!matchesGhidraVersion(extension)) {
				comp.setForeground(getErrorForegroundColor(data.isSelected()));
			}

			return comp;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	}
}
