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

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList; // list keeping track of groups created on this server
	public KeyList keyList; // keeps track of keys belonging to groups 

	// locations of key files
	public static final String PUBLIC_KEY_FILE = "gs_public.key";
	private static final String PRIVATE_KEY_FILE = "gs_private.key";

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");

		// get RSA keys from file or generate them if they do not exist
		generateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
		generateKeys(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE);
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String keyFile = "KeyList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream keyStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		// initialize Bouncy Castle Provider
		Security.addProvider(new BouncyCastleProvider());

		//Open user file to get user list
		try
		{
			//try to read UserList file an write it to UserList object
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();

			//try to read GroupList file and write it to GroupList object
			FileInputStream fis2 = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis2);
			groupList = (GroupList)groupStream.readObject();
			
			//try to read KeyList file and write it to KeyList object
			FileInputStream fis3 = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(fis3);
			keyList = (KeyList) keyStream.readObject();
		}
		// if the userList file doesn't exist, then groupList doesn't either
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter admin username: ");
			String username = console.nextLine();
			System.out.print("Enter admin password: ");
			String password = console.nextLine();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			groupList = new GroupList();
			groupList.addGroup("ADMIN"); //add the first group the the grouplist
			keyList = new KeyList();
			try	{
				keyList.addGroupKey("ADMIN"); //add the first group to the keyList
			} catch (NoSuchAlgorithmException ex) {

			}
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try
		{
			System.out.println("ServerStarted...");

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
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

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin")); //write the grouplist to GroupList.bin
			outStream.writeObject(my_gs.groupList);
			outStream = new ObjectOutputStream(new FileOutputStream("KeyList.bin"));
			outStream.writeObject(my_gs.keyList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					//save user list
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);

				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

				try
				{

					//save group list
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin")); //write the grouplist to GroupList.bin
					outStream.writeObject(my_gs.groupList);

				}
				catch(Exception e1)
				{
					System.err.println("Error: " + e1.getMessage());
					e1.printStackTrace(System.err);
				}
				try
				{

					//save key list
					outStream = new ObjectOutputStream(new FileOutputStream("KeyList.bin")); //write the grouplist to GroupList.bin
					outStream.writeObject(my_gs.keyList);

				}
				catch(Exception e1)
				{
					System.err.println("Error: " + e1.getMessage());
					e1.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
