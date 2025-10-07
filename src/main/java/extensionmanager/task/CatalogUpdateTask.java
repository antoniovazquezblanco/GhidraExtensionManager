package extensionmanager.task;

import extensionmanager.catalog.CatalogUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class CatalogUpdateTask extends Task {

	private boolean success = false;

	public CatalogUpdateTask() {
		super("Update Catalog", false, true, true);
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Updating extension catalog...");
		success = CatalogUtils.update();
	}

	public boolean isSuccess() {
		return success;
	}
}
