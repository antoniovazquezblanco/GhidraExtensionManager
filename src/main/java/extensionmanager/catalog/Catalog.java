package extensionmanager.catalog;

import java.io.Reader;
import java.util.Date;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class Catalog {
	Integer version;
	Date date;
	List<Extension> extensions;

	public static Catalog parse(Reader reader) throws CatalogVersionException {
		Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.S").create();
		Catalog catalog = gson.fromJson(reader, new TypeToken<Catalog>() {
		}.getType());
		if (catalog.version != 0)
			throw new CatalogVersionException();
		return catalog;
	}
}
