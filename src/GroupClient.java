/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.*;

import javax.crypto.*;

public class GroupClient extends Client implements GroupClientInterface {

  // variable for setting response messages
  private String responseMessage = "";

  public String getResponseMessage() {
    return new String(responseMessage);
  }

  private void setResponseMessage(String responseType) {
    responseMessage = ResponseConstants.responseTypeToMessage(responseType);
  }

  public GroupClient() {
    try {
      ObjectInputStream keyReader = new ObjectInputStream(new FileInputStream(GroupServer.PUBLIC_KEY_FILE));
      publicKey = (PublicKey) keyReader.readObject();
      keyReader.close();
    } catch (Exception e) {
      System.err.println("Error while reading group server public key from disk.");
      System.exit(1);
    }
  }

  public UserToken getToken(String username, String password, String fs_ip, int fs_port)
  {
    try
    {
      UserToken token = null;
      Envelope message = null, response = null;

      //Tell the server to return a token.
      message = new Envelope("GET");
      message.addObject(username); // Add user name string
      message.addObject(password); // add password
      message.addObject(fs_ip); // add ip
      message.addObject(fs_port); // add port
      encryptAndWriteMessage(message);

      //Get the response from the server
      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 2)) {
        //Successful response
        if(response.getMessage().equals(ResponseConstants.SUCCESS_GET))
        {
          //If there is a token in the Envelope, return it
          ArrayList<Object> temp = null;
          temp = response.getObjContents();
          token = (UserToken)temp.get(0);
          return token;
        }
      }

      return null;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return null;
    }

  }

  public boolean createUser(String username, String password, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      // Tell the server to create a user
      message = new Envelope("CUSER");
      message.addObject(username); //Add user name string
      message.addObject(password);
      message.addObject(token); //Add the requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        // If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_CUSER))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  public boolean deleteUser(String username, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;

      //Tell the server to delete a user
      message = new Envelope("DUSER");
      message.addObject(username); //Add user name
      message.addObject(token);  //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_DUSER))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  public boolean createGroup(String groupname, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to create a group
      message = new Envelope("CGROUP");
      message.addObject(groupname); //Add the group name string
      message.addObject(token); //Add the requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_CGROUP))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  public boolean deleteGroup(String groupname, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to delete a group
      message = new Envelope("DGROUP");
      message.addObject(groupname); //Add group name string
      message.addObject(token); //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_DGROUP))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  @SuppressWarnings("unchecked")
  public List<String> listMembers(String group, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to return the member list
      message = new Envelope("LMEMBERS");
      message.addObject(group); //Add group name string
      message.addObject(token); //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 2)) {
        //If server indicates success, return the member list
        if(response.getMessage().equals(ResponseConstants.SUCCESS_LIST_MEMBERS))
        {
          return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
        }
      }

      return null;

    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return null;
    }
  }

  public boolean addUserToGroup(String username, String groupname, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to add a user to the group
      message = new Envelope("AUSERTOGROUP");
      message.addObject(username); //Add user name string
      message.addObject(groupname); //Add group name string
      message.addObject(token); //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_ADD_USER_TO_GROUP))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to remove a user from the group
      message = new Envelope("RUSERFROMGROUP");
      message.addObject(username); //Add user name string
      message.addObject(groupname); //Add group name string
      message.addObject(token); //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 1)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_DELETE_USER_FROM_GROUP))
        {
          return true;
        }
      }

      return false;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return false;
    }
  }

  public Key getKey(String groupname, String index, UserToken token)
  {
    try
    {
      Envelope message = null, response = null;
      //Tell the server to remove a user from the group
      message = new Envelope("GETKEY");
      message.addObject(groupname); //Add user name string
      message.addObject(index); //Add group name string
      message.addObject(token); //Add requester's token
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (isValidMessage(response, 2)) {
        //If server indicates success, return true
        if(response.getMessage().equals(ResponseConstants.SUCCESS_GKEY))
        {
        	 return (Key) response.getObjContents().get(0);
          
        }
      }

      return null;
    }
    catch(Exception e)
    {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return null;
    }
  }
  
  public byte[] getTokenSignature(UserToken token) {
    try {
      // System.err.println("token: " + token.getGroups());
      Envelope message = null, response = null;
      message = new Envelope("SIGNTOKEN");
      message.addObject(token);
      encryptAndWriteMessage(message);

      response = readAndDecryptResponse();
      setResponseMessage(response.getMessage());
      if (response.getMessage().equals(ResponseConstants.SUCCESS_SIGNTOKEN)) {
        return (byte[])response.getObjContents().get(0);
      }
      return null;
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
      return null;
    }
  }
}
