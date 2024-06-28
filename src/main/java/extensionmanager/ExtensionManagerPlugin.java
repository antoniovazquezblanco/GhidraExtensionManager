package extensionmanager;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import extensionmanager.ui.ExtensionManagerDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Plugin for plugin management.",
	description = "This plugin allows you to manage your Ghidra extensions from within Ghidra."
)
//@formatter:on
public class ExtensionManagerPlugin extends ProgramPlugin implements ApplicationLevelOnlyPlugin {

	private static final String FRONTENDTOOL_MENU_CONFIGURE_GROUP = "Configure";

	private ExtensionManagerDialog extensionManagerDialog;

	public ExtensionManagerPlugin(PluginTool tool) {
		super(tool);
		setupActions();
	}

	@Override
	public void dispose() {
		super.dispose();
		if (extensionManagerDialog != null) {
			extensionManagerDialog.dispose();
		}
	}

	private void setupActions() {
		DockingAction openExtensionManagerAction = new DockingAction("Extension Manager", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openExtensionManager();
			}
		};

		String[] openExtensionManagerMenuPath = { ToolConstants.MENU_FILE, "Extension manager..." };
		openExtensionManagerAction
				.setMenuBarData(new MenuData(openExtensionManagerMenuPath, FRONTENDTOOL_MENU_CONFIGURE_GROUP));

		if (tool instanceof FrontEndTool) {
			tool.addAction(openExtensionManagerAction);
		}
	}

	private void openExtensionManager() {
		if (extensionManagerDialog == null) {
			extensionManagerDialog = new ExtensionManagerDialog(tool);
		}
		tool.showDialog(extensionManagerDialog);
	}
}
