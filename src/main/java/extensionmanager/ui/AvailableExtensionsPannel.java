package extensionmanager.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableColumn;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.TableSortState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.extensions.ExtensionDetails;

public class AvailableExtensionsPannel extends JPanel {

	private GTableFilterPanel<ExtensionDetails> tableFilterPanel;
	private AvailableExtensionTableModel tableModel;
	private GTable table;

	public AvailableExtensionsPannel(PluginTool tool) {

		super(new BorderLayout());

		tableModel = new AvailableExtensionTableModel(tool);
		tableModel.setTableSortState(TableSortState.createDefaultSortState(AvailableExtensionTableModel.NAME_COL));
		table = new GTable(tableModel);
		table.setPreferredScrollableViewportSize(new Dimension(500, 300));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JScrollPane sp = new JScrollPane(table);
		add(sp, BorderLayout.CENTER);

		tableFilterPanel = new GTableFilterPanel<>(table, tableModel);
		add(tableFilterPanel, BorderLayout.SOUTH);

		TableColumn col = table.getColumnModel().getColumn(AvailableExtensionTableModel.INSTALLED_COL);
		col.setMaxWidth(25);
	}

	public void dispose() {
		tableFilterPanel.dispose();
		table.dispose();
	}

	public AvailableExtensionTableModel getTableModel() {
		return tableModel;
	}

	public GTable getTable() {
		return table;
	}

	public ExtensionDetails getSelectedItem() {
		return tableFilterPanel.getSelectedItem();
	}

	public void refreshTable() {
		tableModel.refreshTable();
	}

	public GTableFilterPanel<ExtensionDetails> getFilterPanel() {
		return tableFilterPanel;
	}
}
