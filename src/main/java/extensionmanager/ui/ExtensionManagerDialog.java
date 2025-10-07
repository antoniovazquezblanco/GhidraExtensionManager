/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package extensionmanager.ui;

import java.awt.BorderLayout;
import java.io.File;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ReusableDialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import extensionmanager.catalog.CatalogUtils;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.extensions.ExtensionInstaller;
import ghidra.util.Msg;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.Icons;

public class ExtensionManagerDialog extends ReusableDialogComponentProvider {

	private static final String LAST_IMPORT_DIRECTORY_KEY = "LastExtensionImportDirectory";

	AvailableExtensionsPannel extensionTablePanel;

	private boolean requireRestart = false;

	public ExtensionManagerDialog(PluginTool tool) {
		super("Extension Manager");
		addWorkPanel(createMainPanel(tool));
	}

	private JComponent createMainPanel(PluginTool tool) {
		JPanel panel = new JPanel(new BorderLayout());

		extensionTablePanel = new AvailableExtensionsPannel(tool);
		panel.add(extensionTablePanel, BorderLayout.CENTER);

		createAddAction(extensionTablePanel);
		createRefreshAction(extensionTablePanel);
		createUpdateCatalogAction(extensionTablePanel);

		addOKButton();

		return panel;
	}

	private void createAddAction(AvailableExtensionsPannel panel) {
		Icon addIcon = Icons.ADD_ICON;
		DockingAction addAction = new DockingAction("ExtensionTools", "AddExtension") {

			@Override
			public void actionPerformed(ActionContext context) {

				// Don't let the user attempt to install anything if they don't have write
				// permissions on the installation dir.
				ResourceFile installDir = Application.getApplicationLayout().getExtensionInstallationDirs().get(0);
				if (!installDir.exists() && !installDir.mkdir()) {
					Msg.showError(this, null, "Directory Error",
							"Cannot install/uninstall extensions: Failed to create extension "
									+ "installation directory: " + installDir);
				}
				if (!installDir.canWrite()) {
					Msg.showError(this, null, "Permissions Error",
							"Cannot install/uninstall extensions: Invalid write permissions on "
									+ "installation directory: " + installDir);
					return;
				}

				GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
				chooser.setLastDirectoryPreference(LAST_IMPORT_DIRECTORY_KEY);
				chooser.setTitle("Select Extension");
				chooser.addFileFilter(new ExtensionFileFilter());

				List<File> files = chooser.getSelectedFiles();
				chooser.dispose();

				if (installExtensions(files)) {
					panel.refreshTable();
					requireRestart = true;
				}
			}
		};

		String group = "extensionTools";
		addAction.setMenuBarData(new MenuData(new String[] { "Add Extension from file" }, addIcon, group));
		addAction.setToolBarData(new ToolBarData(addIcon, group));
		addAction.setDescription("Add extension from file");
		addAction.setEnabled(!Application.inSingleJarMode());
		addAction(addAction);
	}

	private void createRefreshAction(AvailableExtensionsPannel tablePanel) {
		Icon refreshIcon = Icons.REFRESH_ICON;
		DockingAction refreshAction = new DockingAction("ExtensionTools", "RefreshExtensions") {

			@Override
			public void actionPerformed(ActionContext context) {
				tablePanel.refreshTable();
			}
		};

		String group = "extensionTools";
		refreshAction.setMenuBarData(new MenuData(new String[] { "Refresh" }, refreshIcon, group));
		refreshAction.setToolBarData(new ToolBarData(refreshIcon, group));
		refreshAction.setDescription("Refresh extension list");
		addAction(refreshAction);
	}

	private void createUpdateCatalogAction(AvailableExtensionsPannel tablePanel) {
		Icon updateIcon = Icons.DOWN_ICON;
		DockingAction updateAction = new DockingAction("ExtensionTools", "UpdateCatalog") {

			@Override
			public void actionPerformed(ActionContext context) {
				if (CatalogUtils.update()) {
					tablePanel.refreshTable();
				} else {
					Msg.showError(this, null, "Update Failed",
							"Failed to update the extension catalog. Please check your internet connection and try again.");
				}
			}
		};
		String group = "extensionTools";
		updateAction.setMenuBarData(new MenuData(new String[] { "Update catalog" }, updateIcon, group));
		updateAction.setToolBarData(new ToolBarData(updateIcon, group));
		updateAction.setDescription("Update catalog");
		updateAction.setEnabled(!Application.inSingleJarMode());
		addAction(updateAction);
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected void dialogClosed() {
		super.dialogClosed();

		if (extensionTablePanel.getTableModel().hasModelChanged() || requireRestart) {
			Msg.showInfo(this, null, "Extensions Changed!",
					"Please restart Ghidra for extension changes to take effect.");
		}
	}

	private boolean installExtensions(List<File> files) {
		boolean didInstall = false;
		for (File file : files) {

			// A sanity check for users that try to install an extension from a source
			// folder
			// instead of a fully built extension.
			if (new File(file, "build.gradle").isFile()) {
				Msg.showWarn(this, null, "Invalid Extension",
						"The selected extension "
								+ "contains a 'build.gradle' file.\nGhidra does not support installing "
								+ "extensions in source form.\nPlease build the extension and try again.");
				continue;
			}

			boolean success = ExtensionInstaller.install(file);
			didInstall |= success;
		}
		return didInstall;
	}

	private class ExtensionFileFilter implements GhidraFileFilter {
		@Override
		public String getDescription() {
			return "Ghidra Extension";
		}

		@Override
		public boolean accept(File f, GhidraFileChooserModel model) {
			return f.isDirectory() || ExtensionUtils.isExtension(f);
		}
	}
}
