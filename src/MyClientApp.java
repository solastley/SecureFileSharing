/* This is a command line interface application that will do the work of using the GroupClient
* and FileClient to allow the user to to connect and interact with the GroupServer and FileServer
*/

import java.security.Key;
import java.util.Scanner;
import java.util.Iterator;
import java.util.List;
import java.io.IOException;
import java.io.File;
import java.security.*;
import javax.crypto.*;

import java.io.FileOutputStream;
import java.io.FileWriter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MyClientApp {

	// constants for possible GroupClient actions
	private final int GET_TOKEN = 1;
	private final int CREATE_USER = 2;
	private final int DELETE_USER = 3;
	private final int CREATE_GROUP = 4;
	private final int DELETE_GROUP = 5;
	private final int ADD_USER_TO_GROUP = 6;
	private final int DELETE_USER_FROM_GROUP = 7;
	private final int LIST_MEMBERS = 8;
	private final int CONNECT_TO_FILE_SERVER = 9;
	private final int GET_GROUP_KEY = 10;
	private final int ENCRYPT_FILE = 11;
	private final int DECRYPT_FILE = 12;
	private final int QUIT_APP = 13;

	// constants for possible FileClient actions
	private final int LIST_FILES = 1;
	private final int UPLOAD = 2;
	private final int DOWNLOAD = 3;
	private final int DELETE = 4;
	private final int SWITCH_TO_GROUP_SERVER = 5;
	private final int QUIT_APPF = 6;

	private FileClient fc = new FileClient();
	private GroupClient gc = new GroupClient();
	private Scanner in = new Scanner(System.in);
	private String username = null;
	private String password = null;
	private UserToken userToken = null;
	private Key userKey = null;
	// private byte[] tokenSignature = null;

	private static String groupServerIp = null;
	private static int groupServerPort = -1;
	private static String fileServerIp = null;
	private static int fileServerPort = -1;
	private static String encryptionServerIp = null;
	private static int encryptionServerPort = -1;

	public MyClientApp() {

		// connect to group server by default, user always needs a token first
		if (!gc.connect(groupServerIp, groupServerPort, false)) {
			System.exit(1);
		}

		int userAction;
		while (true)
		{
			// display user options
			if (gc.isConnected()) {
				printGroupServerMenu();
			}
			else if (fc.isConnected()) {
				printFileServerMenu();
			}
			else {
				System.out.println("Connection to the servers has been interrupted.");
				System.exit(1);
			}

			// get user action
			try {
				userAction = Integer.parseInt(in.nextLine());
			}
			catch (Exception e) {
				userAction = -1;
			}

			// handle actions
			if (gc.isConnected()) {
				if (!handleGroupServerAction(userAction)) {
					break; // when handler returns false, user wants to quit
				}
			}
			else if (fc.isConnected()) {
				if (!handleFileServerAction(userAction)) {
					break;
				}
			}
			else {
				System.out.println("Connection to the servers has been interrupted.");
				System.exit(1);
			}
		}

		System.out.println("Goodbye.");
		gc.disconnect();
		fc.disconnect();
		System.exit(0);
	}

	private boolean handleGroupServerAction(int actionType) {
		switch (actionType) {
			case GET_TOKEN:	{
				System.out.println("Please login to the server to obtain a token.");
				System.out.print("Username: ");
				username = in.nextLine();
				System.out.print("Password: ");
				password = in.nextLine();

				System.out.println("Special token for group server actions only?");
				System.out.println("(enter '1' for special token, '0' for normal token):");
				boolean valid = false;
				int choice = Integer.parseInt(in.nextLine());
				while (!valid) {
					if (choice == 1) {
						userToken = gc.getToken(username, password, "0.0.0.0", 0);
						valid = true;
					} else if (choice == 0) {
						userToken = gc.getToken(username, password, fileServerIp, fileServerPort);
						valid = true;
					} else {
						System.out.println("Invalid choice.");
						System.out.println("(enter '1' for special token, '0' for normal token):");
						choice = Integer.parseInt(in.nextLine());
					}
				}

				// try to get a token, display result
				System.out.println(gc.getResponseMessage());

				break;
			}
			case CREATE_USER: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Enter a value for the new username: ");
					String newUser = in.nextLine();
					System.out.print("Enter the new user's password: ");
					String newPassword = in.nextLine();

					// try to create user, display result
					gc.createUser(newUser, newPassword, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case DELETE_USER: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Enter the username to delete: ");
					String userToDelete = in.nextLine();

					// try to delete user, display result
					gc.deleteUser(userToDelete, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case CREATE_GROUP: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Enter the group name to create: ");
					String newGroup = in.nextLine();

					// try to create group, display result
					gc.createGroup(newGroup, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case DELETE_GROUP: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Enter the group name to delete: ");
					String groupToDelete = in.nextLine();

					// try to delete group, display response
					gc.deleteGroup(groupToDelete, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case ADD_USER_TO_GROUP: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Please enter the username to add: ");
					String userToAdd = in.nextLine();
					System.out.print("Please enter the group you'd like to add this user to: ");
					String groupToAddTo = in.nextLine();

					// try to add user to group, display response
					gc.addUserToGroup(userToAdd, groupToAddTo, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case DELETE_USER_FROM_GROUP: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Please enter the username to delete: ");
					String userToDelete = in.nextLine();
					System.out.print("Please enter the group you'd like to remove this user from: ");
					String groupToDeleteFrom = in.nextLine();

					// try to delete user from group, display response
					gc.deleteUserFromGroup(userToDelete, groupToDeleteFrom, userToken);
					System.out.println(gc.getResponseMessage());
				}

				break;
			}
			case LIST_MEMBERS: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					System.out.print("Please enter the name of the group: ");
					String groupToList = in.nextLine();
					List<String> members = gc.listMembers(groupToList, userToken);
					if (members != null) {
						if (members.size() == 0) {
							System.out.println("There are no members in this group yet.");
						}
						else {
							System.out.println("Members of group " + groupToList + ":");
							Iterator<String> memberIter = members.iterator();
							while (memberIter.hasNext()) {
								String memberName = (String) memberIter.next();
								System.out.println(memberName);
							}
						}
					}
					else {
						System.out.println(gc.getResponseMessage());
					}
				}

				break;
			}
			case GET_GROUP_KEY: {
					if (userToken == null) {
						System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
					}
					else {
						System.out.print("Please enter the name of the group: ");
						String group = in.nextLine();
						System.out.println("Please enter the index for the group key: (-1) to get most recent");
						String index = in.nextLine();
						userKey = gc.getKey(group, index, userToken);
						if(userKey!=null)
						{
							System.out.println("Key obtained successfully, you may now encrypt or decrypt a file");
						}
						else
						{
							System.out.println("Error retrieving key");
						}
					break;
				}
			}
			case ENCRYPT_FILE: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					if(userKey==null)
					{
						System.out.println("You must first obtain a key");
					}
					else
					{
						System.out.println("Enter the filename to encrypt ");
						String filename = in.nextLine();
						encryptFile(filename,userKey);
					}
				}
				break;
			}
			case DECRYPT_FILE: {
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					if(userKey==null)
					{
						System.out.println("You must first obtain a key");
					}
					else
					{
						System.out.println("Enter the filename to decrypt ");
						String filename = in.nextLine();
						decryptFile(filename,userKey);
					}
				}
				break;
			}
			case CONNECT_TO_FILE_SERVER: {
				// Make sure they have a valid token, if not they cannot use the FileServer
				if (userToken == null) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else if ((!userToken.getFS_IP().equals(fileServerIp))
					&& (userToken.getFS_port() != (fileServerPort))) {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}
				else {
					// Try to connect to file server (using hardcoded values for now)
					if (fc.connect(fileServerIp, fileServerPort, true)) {
						System.out.println("You are connected to the file server.");

						// Disconnect from GroupServer
						gc.disconnect();
					}
					else {
						System.out.println("Failed to connect to the file server.");
					}
				}

				break;
			}
			case QUIT_APP: {
				return false;
			}
			default: {
				System.out.println("Please enter a valid number.");
			}
		}

		return true;
	}

	private boolean handleFileServerAction(int actionType) {
		switch (actionType) {
			case LIST_FILES: {
				List<String> userFiles = fc.listFiles(userToken);
				if (userFiles != null) {
					if (userFiles.size() != 0) {
						System.out.println("Your files:");
						Iterator fileIter = userFiles.iterator();
						while (fileIter.hasNext()) {
							String filename = (String) fileIter.next();
							System.out.println(filename);
						}
					}
					else {
						System.out.println("You currently have no files.");
					}
				}
				else {
					System.out.println(ResponseConstants.FAIL_BAD_TOKEN_MSG);
				}

				break;
			}
			case UPLOAD: {
				System.out.print("Enter the source path of the file: ");
				String sourceFile = in.nextLine();
				System.out.print("Enter the destination path of the file: ");
				String destFile = in.nextLine();
				System.out.print("Enter the group to add this file to: ");
				String groupName = in.nextLine();

				String en_file = "en_".concat(sourceFile);
				encryptFile(sourceFile, userKey);
				if (fc.upload(en_file, destFile, groupName, userToken)) {
					System.out.println("File uploaded successfully.");
					new File(en_file).delete();
				}
				else {
					System.out.println("There was a problem uploading your file.");
				}

				break;
			}
			case DOWNLOAD: {
				System.out.print("Enter the source path of the file: ");
				String sourceFile = in.nextLine();
				System.out.print("Enter the destination path of the file: ");
				String destFile = in.nextLine();

				if (fc.download(sourceFile, destFile, userToken)) {
					System.out.println("File downloaded successfully.");
				}
				else {
					System.out.println("There was a problem downloading your file.");
				}

				break;
			}
			case DELETE: {
				System.out.print("Enter the source path of the file: ");
				String sourceFile = in.nextLine();

				if (fc.delete(sourceFile, userToken)) {
					System.out.println("File deleted successfully.");
				}
				else {
					System.out.println("There was a problem deleting your file.");
				}

				break;
			}
			case SWITCH_TO_GROUP_SERVER: {
				if (gc.connect(groupServerIp, groupServerPort, false)) {
					System.out.println("You are connected to the group server.");

					// disconnect from file server
					fc.disconnect();
				}

				break;
			}
			case QUIT_APPF: {
				return false;
			}
			default: {
				System.out.println("Please enter a valid number.");
			}
		}

		return true;
	}

	private void printGroupServerMenu() {
		System.out.println("\nPlease enter the corresponding integer of your choice:");
		System.out.println("1. Obtain a token");
		System.out.println("2. Create a user");
		System.out.println("3. Delete a user");
		System.out.println("4. Create a group");
		System.out.println("5. Delete a group");
		System.out.println("6. Add a user to an existing group");
		System.out.println("7. Remove a user from an existing group");
		System.out.println("8. List members of a group");
		System.out.println("9. Connect to File Server");
		System.out.println("10. Get group key");
		System.out.println("11. Encrypt a file");
		System.out.println("12. Decrypt a file");
		System.out.println("13. Quit the app");
	}

	private void printFileServerMenu() {
		System.out.println("\nPlease enter the corresponding integer of your choice:");
		System.out.println("1. Get list of files you have access to");
		System.out.println("2. Upload a file to be shared with a group");
		System.out.println("3. Download a file");
		System.out.println("4. Delete a file");
		System.out.println("5. Switch to the Group Server");
		System.out.println("6. Quit App");
	}

	public static void main(String [] args)
	{
		if (args.length != 4) {
			System.out.println("Please specify the IP address and port numbers for the group and file servers.");
			return;
		} else {
			try {
				groupServerIp = args[0];
				groupServerPort = Integer.parseInt(args[1]);
				fileServerIp = args[2];
				fileServerPort = Integer.parseInt(args[3]);
			} catch (NumberFormatException e) {
				System.out.println("The specified group or file server port number is invalid.");
				return;
			}
		}

		new MyClientApp();
	}

	private boolean encryptFile(String filename, Key key) {
		try {
			String en_filename = "en_".concat(filename);
     	 	File outFile = new File(en_filename);
     	 	FileOutputStream ostr = new FileOutputStream(outFile);

            Cipher cipher;
            cipher = Cipher.getInstance("AES");

            File file = new File(filename);
      		Path path = file.toPath();
            byte[] filebytes = Files.readAllBytes(path);

            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(filebytes);

            ostr.write(encrypted);
      		ostr.close();
            return true;
        } catch(Exception e) {
            System.out.println("Exception");
           	return false;
        }
	}

	private boolean decryptFile(String filename, Key key) {
		try {
     	 	File outFile = new File(filename);
     	 	FileWriter writer = new FileWriter(outFile);
            Cipher cipher;
            cipher = Cipher.getInstance("AES");

            File file = new File(filename);
      		Path path = file.toPath();
            byte[] filebytes = Files.readAllBytes(path);

            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(filebytes);

            writer.write(new String(decrypted));
      		writer.close();
            return true;
        } catch(Exception e) {
            System.out.println("Exception");
            return false;
        }
	}
}
