import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;

public class GoogleTest implements Runnable
{

	private static PrintStream flog;

	private static SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");

	private String url;

	private GoogleTest(String url)
	{
		this.url = url;
	}

	public void run()
	{
		String log = "Start in: " + dateformat.format(new Date()) + "\tEnd in: ";
		String status = "Success";
		try
		{
			InputStream in = new URL(url).openStream();
			while(in.read() >= 0);
		}
		catch (MalformedURLException e)
		{
			status = e.getMessage();
		}
		catch (IOException e)
		{
			status = e.getMessage();
		}
		finally
		{
			log += dateformat.format(new Date()) + "\tStatus: " + status + "\tURL: " + url;
			flog.println(log);
			flog.flush();
		}
	}

	public static void main(String[] args) throws IOException, InterruptedException
	{
		Properties props = new Properties();
		props.load(GoogleTest.class.getResourceAsStream("GoogleTest.properties"));
		String[] urls = props.getProperty("urls").split(" ");
		int interval = Integer.parseInt(props.getProperty("interval")) * 1000;
		int times = Integer.parseInt(props.getProperty("times"));
		flog = new PrintStream(new FileOutputStream(props.getProperty("log")));
		for(int i = 0; i < times; i++)
		{
			for(int j = 0; j < urls.length; j++)
			{
				new Thread(new GoogleTest(urls[j])).start();
				Thread.sleep(interval);
			}
		}
	}

}
