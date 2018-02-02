/* This thread does all the work. It communicates with the client through Envelopes.
*
*/
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;

import javax.crypto.*;

// These have been added for RSA signature
import java.lang.StringBuilder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;


public class GroupThread extends ServerThread
{
	private final Socket socket;
	private String responseType;
	private GroupServer server;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		server = _gs;
		responseType = "";
		privateKey = server.getPrivateKey();

		try {
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());
		} catch (Exception e) {
			System.err.println("Error creating socket input and output streams.");
			System.exit(1);
		}
	}

	public void run()
	{
		boolean proceed = true;
		Envelope message = null, response = null;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

			// establish session key with client
			if (!establishSessionKey()) {
				System.err.println("Error occurred while attempting to establish session key.");
				return;
			}

			do
			{
				// read Envelope from client, decrypt with shared AES key
				message = readAndDecryptMessage();
				System.out.println("Request received: " + message.getMessage());

				if (message.getMessage().equals("GET"))//Client wants a token
				{
					if (isValidMessage(message, 5)) {
						String username = (String) message.getObjContents().get(0); // Get the username
						String password = (String) message.getObjContents().get(1); // get password
						String fs_ip = (String) message.getObjContents().get(2);
						int fs_port = (int) message.getObjContents().get(3);
						UserToken yourToken = createToken(username, password, fs_ip, fs_port); //Create a token
						if (yourToken != null) {
							response = new Envelope(ResponseConstants.SUCCESS_GET);
							response.addObject(yourToken);
						} else {
							response = new Envelope(ResponseConstants.FAIL_USER_NO_EXIST);
						}
					}
					else
					{
						response = new Envelope(ResponseConstants.FAIL_GET);
						response.addObject(null);
					}
				}
				else if (message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					response = new Envelope(ResponseConstants.FAIL_CUSER);

					if (isValidMessage(message, 4)) {
						String username = (String) message.getObjContents().get(0); // Extract the username
						String password = (String) message.getObjContents().get(1);
						UserToken yourToken = (UserToken) message.getObjContents().get(2); // Extract the token

						if (createUser(username, password, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_CUSER); //Success
						}
						else
						{
							// responseType set by createUser
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					response = new Envelope(ResponseConstants.FAIL_DUSER);

					if (isValidMessage(message, 3)) {
						String username = (String)message.getObjContents().get(0); //Extract the username
						UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

						if (deleteUser(username, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_DUSER); //Success
						}
						else
						{
							// responseType set by deleteUser
							response = new Envelope(responseType);
						}
					}
				}
				else if (message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					response = new Envelope(ResponseConstants.FAIL_CGROUP);

					if (isValidMessage(message, 3)) {
						String groupname = (String) message.getObjContents().get(0);
						UserToken yourToken = (UserToken) message.getObjContents().get(1);

						if (createGroup(groupname, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_CGROUP); //Success
						}
						else
						{
							// responseType is set by createGroup
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					response = new Envelope(ResponseConstants.FAIL_DGROUP);

					if (isValidMessage(message, 3)) {
						String groupname = (String) message.getObjContents().get(0);
						UserToken yourToken = (UserToken) message.getObjContents().get(1);

						if (deleteGroup(groupname, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_DGROUP); //Success
						}
						else
						{
							// responseType is set by deleteGroup
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					response = new Envelope(ResponseConstants.FAIL_LIST_MEMBERS);

					if (isValidMessage(message, 3)) {
						String groupname = (String) message.getObjContents().get(0);
						UserToken yourToken = (UserToken) message.getObjContents().get(1);

						List<String> members = listMembers(groupname, yourToken);
						if (members != null)
						{
							response = new Envelope(ResponseConstants.SUCCESS_LIST_MEMBERS); //Success
							response.addObject(members);
						}
						else
						{
							// responseType set by listMembers
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					response = new Envelope(ResponseConstants.FAIL_ADD_USER_TO_GROUP);

					if (isValidMessage(message, 4)) {
						String username = (String) message.getObjContents().get(0);
						String groupname = (String) message.getObjContents().get(1);
						UserToken yourToken = (UserToken) message.getObjContents().get(2);

						if (addUserToGroup(username, groupname, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_ADD_USER_TO_GROUP); //Success
						}
						else
						{
							// responseType set by addUserToGroup
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					response = new Envelope(ResponseConstants.FAIL_DELETE_USER_FROM_GROUP);

					if (isValidMessage(message, 4)) {
						String username = (String) message.getObjContents().get(0);
						String groupname = (String) message.getObjContents().get(1);
						UserToken yourToken = (UserToken) message.getObjContents().get(2);

						if (removeUserFromGroup(username, groupname, yourToken))
						{
							response = new Envelope(ResponseConstants.SUCCESS_DELETE_USER_FROM_GROUP); //Success
						}
						else
						{
							// responseType set by removeUserFromGroup
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("GETKEY")) //Client wants to get a key for a group
				{
					response = new Envelope(ResponseConstants.FAIL_GKEY);

					if (isValidMessage(message, 4)) {
						String groupname = (String) message.getObjContents().get(0);
						String index = (String) message.getObjContents().get(1);
						UserToken yourToken = (UserToken) message.getObjContents().get(2);

						Key tempKey = getKey(groupname, index, yourToken);
						if (tempKey!=null)
						{
							response = new Envelope(ResponseConstants.SUCCESS_GKEY); //Success
							response.addObject(tempKey);
						}
						else
						{
							// responseType set 
							response = new Envelope(responseType);
						}
					}
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
				}

				// encrypt the response and send it
				if (proceed) {
					encryptAndWriteResponse(response);
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	// Method to create tokens
	private UserToken createToken(String username, String password, String fs_ip, int fs_port)
	{
		// Check that user exists and password is correct
		if (server.userList.checkUser(username, password))
		{
			// Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = 
				new Token(server.name, username, server.userList.getUserGroups(username), fs_ip, fs_port);
			try {
				yourToken.setSignature(privateKey);
			} catch (Exception e) {
				System.err.println("Problem signing token");
			}
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	// Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken)
	{
		// validate requester's token
		if (server.validateToken(yourToken))
		{
			//Get the user's groups
			String requester = yourToken.getSubject();
			ArrayList<String> temp = server.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if (temp.contains("ADMIN"))
			{
				// Does user already exist?
				if (server.userList.checkUserExists(username))
				{
					responseType = ResponseConstants.FAIL_USER_EXIST;
					return false; //User already exists
				}
				else
				{
					server.userList.addUser(username, password);
					return true;
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_NO_ADMIN;
				return false; //requester not an administrator
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			return false; // requester has an invalid token
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		// does requester have a valid token?
		if (server.validateToken(yourToken))
		{
			String requester = yourToken.getSubject();
			ArrayList<String> temp = server.userList.getUserGroups(requester);
			String fs_ip = yourToken.getFS_IP();
			int fs_port = yourToken.getFS_port();
			//requester needs to be an administer
			if (temp.contains("ADMIN"))
			{
				//Does user exist?
				if (server.userList.checkUserExists(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for (int index = 0; index < server.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(server.userList.getUserGroups(username).get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for (int index = 0; index < server.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(server.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for (int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), 
							new Token(server.name, username, deleteOwnedGroup, fs_ip, fs_port));
					}

					//Delete the user from the user list
					server.userList.deleteUser(username);

					return true;
				}
				else
				{
					responseType = ResponseConstants.FAIL_USER_NO_EXIST;
					return false; //User does not exist
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_NO_ADMIN;
				return false; //requester is not an administer
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			return false; //requester does not exist
		}
	}

	// method to create a group
	private boolean createGroup(String groupname, UserToken yourToken) throws NoSuchAlgorithmException
	{
		// Check if requester has a valid token
		if(server.validateToken(yourToken))
		{
			// should perform a check here to make sure group doesn't already exist, need to get a list of groups
			if(!server.groupList.hasGroup(groupname))
			{
				String requester = yourToken.getSubject();
				// Since user is valid they are allowed to create a group, no special permissions needed here
				server.userList.addGroup(requester, groupname); // add the group to the list
				server.userList.addOwnership(requester, groupname); // specify the owner of the token having ownership of the new group
				server.groupList.addGroup(groupname); // add the created group to the server's list of groups
				server.keyList.addGroupKey(groupname); // add the created group to the keyList

				return true;
			}
			else
			{
				responseType = ResponseConstants.FAIL_GROUP_EXIST;
				// the groupname already exists
				return false;
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			// User does not exist
			return false;
		}
	}

	// method to delete a group
	private boolean deleteGroup(String groupname, UserToken yourToken)
	{
		// Does requester have a valid token?
		if(server.validateToken(yourToken))
		{
			// does group exist?
			if(server.groupList.hasGroup(groupname))
			{
				String requester = yourToken.getSubject();
				ArrayList<String> temp = server.userList.getUserOwnership(requester);
				// does the user own the group?
				if(temp.contains(groupname))
				{
					// First remove ownership of the group from the requester
					server.userList.removeOwnership(requester, groupname);
					// Must loop through every user on the server, and remove them from the group if they belong to it
					temp = server.userList.getUsers();
					ArrayList<String> temp2;
					for(int i=0; i<temp.size(); i++)
					{
						// check to see if the user is in the group being deleted, if so remove them from that group
						temp2 = server.userList.getUserGroups(temp.get(i));
						if(temp2.contains(groupname))
						{
							server.userList.removeGroup(temp.get(i), groupname);
						}
					}

					// remove group from group list
					server.groupList.removeGroup(groupname);

					return true;
				}
				else
				{
					responseType = ResponseConstants.FAIL_NO_OWNER;
					// the user is not an owner of the group and cannot delete it
					return false;
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_GROUP_NO_EXIST;
				return false; // this is not a valid group
			}

		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			//requester does not exist
			return false;
		}
	}

	// method to return a list of members in a group
	private List<String> listMembers(String groupname, UserToken yourToken)
	{
		//Does requester have a valid token?
		if (server.validateToken(yourToken))
		{
			//does group exist?
			if(server.groupList.hasGroup(groupname))
			{
				String requester = yourToken.getSubject();
				ArrayList<String> temp = server.userList.getUserOwnership(requester);
				List<String> members = new ArrayList<String>();
				//Does the user own the requested group
				if(temp.contains(groupname))
				{
					//Must loop through every user on the server, and add them to members if they belong to it
					temp = server.userList.getUsers();
					ArrayList<String> temp2;
					for(int i=0; i<temp.size(); i++)
					{
						//check to see if the user is in the group
						temp2 = server.userList.getUserGroups(temp.get(i));
						if(temp2.contains(groupname))
						{
							members.add(temp.get(i));
						}
					}

					return members;
				}
				else
				{
					responseType = ResponseConstants.FAIL_NO_OWNER;
					return null; //the user is not the owner, so cannot get the userlist
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_GROUP_NO_EXIST;
				return null; //the group does not exist
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			return null; //the requester doesn't exist
		}
	}

	// method to add a user to a group
	private boolean addUserToGroup(String username, String groupname, UserToken yourToken)
	{
		// Does requester have a valid token?
		if (server.validateToken(yourToken))
		{
			// does group exist?
			if(server.groupList.hasGroup(groupname))
			{
				String requester = yourToken.getSubject();
				ArrayList<String> temp = server.userList.getUserOwnership(requester);
				// Does the user own the requested group
				if(temp.contains(groupname))
				{
					// does the user trying to be added exist?
					if(server.userList.checkUserExists(username))
					{
						// does the user trying to be added not already belong?
						if (!server.userList.getUserGroups(username).contains(groupname)) {
							// add the user to the group
							server.userList.addGroup(username, groupname);

							return true;
						}
						else
						{
							responseType = ResponseConstants.FAIL_MEMBER;
							return false;
						}
					}
					else
					{
						responseType = ResponseConstants.FAIL_USER_NO_EXIST;
						// the user trying being added does not exist
						return false;
					}
				}
				else
				{
					responseType = ResponseConstants.FAIL_NO_OWNER;
					// the requester is not the owner of the group
					return false;
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_GROUP_NO_EXIST;
				// the group does not exist
				return false;
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			// the requester does not exist
			return false;
		}
	}

	// method to remove a user from a group
	private boolean removeUserFromGroup(String username, String groupname, UserToken yourToken)
	{
		// Does requester have a valid token?
		if(server.validateToken(yourToken))
		{
			// does group exist?
			if(server.groupList.hasGroup(groupname))
			{
				String requester = yourToken.getSubject();
				ArrayList<String> temp = server.userList.getUserOwnership(requester);
				// Does the user own the requested group
				if(temp.contains(groupname))
				{
					// does the user trying to be removed exist?
					if(server.userList.checkUserExists(username))
					{
						// is the user trying to be removed actually belong to this group?
						if (server.userList.getUserGroups(username).contains(groupname)) {
							// remove the user from the group
							server.userList.removeGroup(username, groupname);
							try {
								server.keyList.addGroupKey(groupname); //generating a new key for that group upon membership revocation
							} catch (NoSuchAlgorithmException e) {
								
								e.printStackTrace();
							}
							return true;
						}
						else
						{
							responseType = ResponseConstants.FAIL_NO_MEMBER;
							return false;
						}
					}
					else
					{
						responseType = ResponseConstants.FAIL_USER_NO_EXIST;
						// the user trying to be removed does not exist
						return false;
					}
				}
				else
				{
					responseType = ResponseConstants.FAIL_NO_OWNER;
					// the requester is not the owner of the group
					return false;
				}
			}
			else
			{
				responseType = ResponseConstants.FAIL_GROUP_NO_EXIST;
				// the group does not exist
				return false;
			}
		}
		else
		{
			responseType = ResponseConstants.FAIL_BAD_TOKEN;
			// the requester does not exist
			return false;
		}
	}
	
	private Key getKey(String groupname, String index, UserToken yourToken)
	{
		
		// Does requester have a valid token?
				if (server.validateToken(yourToken))
				{
					// does group exist?
					if(server.groupList.hasGroup(groupname))
					{
						String requester = yourToken.getSubject();
						ArrayList<String> temp = server.userList.getUserGroups(requester);
						// Is the user a member of the group? 
						if(temp.contains(groupname))
						{
							return server.keyList.getKeyByIndex(groupname, index);
						}
						else
						{
							responseType = ResponseConstants.FAIL_GKEY;
							return null;
						}
					}
					else
					{
						responseType = ResponseConstants.FAIL_GROUP_NO_EXIST;
						// the group does not exist
						return null;
					}
				}
				else
				{
					responseType = ResponseConstants.FAIL_BAD_TOKEN;
					// the requester does not exist
					return null;
				}
		
	}
}
