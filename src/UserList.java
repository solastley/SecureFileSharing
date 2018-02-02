/* This list represents the users on the server */

import java.util.*;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class UserList implements java.io.Serializable {

	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, User> list = new Hashtable<String, User>();
	private ArrayList<String> users = new ArrayList<String>(); //arraylist to keep a straight up list of users on the server

	public synchronized void addUser(String username, String password)
	{
		User newUser = new User(password);
		list.put(username, newUser);
		users.add(username);
	}

	public synchronized void deleteUser(String username)
	{
		list.remove(username);
		users.remove(username);
	}

	/**
	* This method checks that a user exists and that the their password matches
	* the password passed to this method.
	* @param username the user to check
	* @param password the password to check for this user
	* @return true if this user exists and the passed password is correct
	*/
	public synchronized boolean checkUser(String username, String password)
	{
		if (list.containsKey(username))
		{
			User currUser = (User) list.get(username);

			// only return true if passed the correct password
			return currUser.checkPassword(password);
		}
		else
		{
			return false;
		}
	}

	/**
	* This method only checks for the existence of a user.
	* @param username the user to check for
	* @return true if the user exists, otherwise false
	*/
	public synchronized boolean checkUserExists(String username) {
		if (list.containsKey(username)) {
			return true;
		}

		return false;
	}

	public synchronized ArrayList<String> getUserGroups(String username)
	{
		return list.get(username).getGroups();
	}

	public synchronized ArrayList<String> getUserOwnership(String username)
	{
		return list.get(username).getOwnership();
	}

	public synchronized void addGroup(String user, String groupname)
	{
		list.get(user).addGroup(groupname);
	}

	public synchronized void removeGroup(String user, String groupname)
	{
		list.get(user).removeGroup(groupname);
	}

	public synchronized void addOwnership(String user, String groupname)
	{
		list.get(user).addOwnership(groupname);
	}

	public synchronized void removeOwnership(String user, String groupname)
	{
		list.get(user).removeOwnership(groupname);
	}
	/* Added this method so the server can loop through the list of users
	*  when it needs to remove them all from a group that has been deleted
	*/
	public synchronized ArrayList<String> getUsers()
	{
		return users;
	}


	class User implements java.io.Serializable {

		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;

		// random salt for this user
		private static final int SALT_LENGTH_IN_BYTES = 16;
		private byte[] salt = new byte[SALT_LENGTH_IN_BYTES];

		// store hash of password and salt, not the password itself
		private String hash = null;

		// time of last password check for this user
		private Date lastPasswordCheck;

		// minimum amount of time between password checks
		private static final int MIN_WAIT_TIME_IN_MILLISECONDS = 1000;

		public User(String password)
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();

			// generate random salt for this user
			try {
				SecureRandom randomVal = SecureRandom.getInstance("SHA1PRNG");
				randomVal.nextBytes(salt);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error using the SHA1PRNG algorithm to generate salt.");
			}

			// generate strong hash of password for this user
			hash = createHash(password);

			// initialize time of last password check to current time
			lastPasswordCheck = new Date();
		}

		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

		/**
		* This method attempts to verify a user's password.
		* @param password to be compared to the stored password info for this user
		* @return true if the password is correct for this user, otherwise false
		*/
		public boolean checkPassword(String password) {
			// limit password checks to one per second to disable online attacks
			long milliseconds = new Date().getTime() - lastPasswordCheck.getTime();
			if (milliseconds < MIN_WAIT_TIME_IN_MILLISECONDS) {
				return false;
			} else {
				lastPasswordCheck = new Date();
			}

			// generate hash using the password to be validated
			String testHash = createHash(password);

			// return comparison of result with the stored hash for this user
			return testHash.equals(hash);
		}

		/**
		* This method generates a secure hash of a user's password and random salt
		* using the SHA-256 hashing algorithm.
		* @param password the user's password to be hashed
		* @return the secure hash to be stored for this user
		*/
		private String createHash(String password) {
			String generatedHash = null;
			try {
				// initialize MessageDigest with random salt for this user
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(salt);

				// generate digest
				byte[] passwordBytes = password.getBytes();
				byte[] digest = md.digest(passwordBytes);

				// transform raw bytes to String
				String secureHash = bytesToString(digest);

				return secureHash;
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error using the SHA-256 algorithm while hashing user password.");
				return null;
			}
		}

		/**
		* This method converts an array of bytes to a readable String.
		* @param bytes the bytes to convert
		* @return the bytes converted to a readable String
		*/
		private String bytesToString(byte[] bytes) {
			StringBuilder result = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				result.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}

			return result.toString();
		}
	}
}
