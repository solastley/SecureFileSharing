/* Group server. Server loads the users from UserList.bin.
* If user list does not exists, it creates a new list and makes the user the server administrator.
* On exit, the server saves the user list to file.
*/

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

// bouncy castle provider
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptionServer extends Server {

	public static final int SERVER_PORT = 9876;

	// Location of key files
	public static final String PUBLIC_KEY_FILE = "es_public.key";
	private static final String PRIVATE_KEY_FILE = "es_private.key";

	public EncryptionServer() {
		super(SERVER_PORT, "EncryptionServer");

		// get RSA keys from file or generate them if they do not exist
		generateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
	}

	public EncryptionServer(int _port) {
		super(_port, "EncryptionServer");
	}

	public void start() {
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		// runtime.addShutdownHook(new ShutDownListener(this));

		// initialize Bouncy Castle Provider
		Security.addProvider(new BouncyCastleProvider());

		//Open user file to get user list
		try
		{

		}
		catch(Exception e)
		{

		}

		try
		{
			System.out.println("ServerStarted...");

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			EncryptionThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new EncryptionThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

