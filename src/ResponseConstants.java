import java.util.HashMap;

/* This class encapsulates error messages to deliver to MyClientApp */

public final class ResponseConstants {

  private ResponseConstants() {
    // restrict instantiation
  }

  // generic error response types
  public static final String FAIL_NO_ADMIN = "FAIL_NO_ADMIN";
  public static final String FAIL_BAD_TOKEN = "FAIL_BAD_TOKEN";
  public static final String FAIL_NO_OWNER = "FAIL_NO_OWNER";
  public static final String FAIL_USER_EXIST = "FAIL_USER_EXIST";
  public static final String FAIL_GROUP_EXIST = "FAIL_GROUP_EXIST";
  public static final String FAIL_USER_NO_EXIST = "FAIL_USER_NO_EXIST";
  public static final String FAIL_GROUP_NO_EXIST = "FAIL_GROUP_NO_EXIST";
  public static final String FAIL_MEMBER = "FAIL_MEMBER";
  public static final String FAIL_NO_MEMBER = "FAIL_NO_MEMBER";

  // response types for specific kinds of requests
  public static final String FAIL_GET = "FAIL_GET";
  public static final String SUCCESS_GET = "SUCCESS_GET";
  public static final String FAIL_SIGNTOKEN = "FAIL_SIGNTOKEN";
  public static final String SUCCESS_SIGNTOKEN = "SUCCESS_SIGNTOKEN";
  public static final String FAIL_CUSER = "FAIL_CUSER";
  public static final String SUCCESS_CUSER = "SUCCESS_CUSER";
  public static final String FAIL_DUSER = "FAIL_DUSER";
  public static final String SUCCESS_DUSER = "SUCCESS_DUSER";
  public static final String FAIL_CGROUP = "FAIL_CGROUP";
  public static final String SUCCESS_CGROUP = "SUCCESS_CGROUP";
  public static final String FAIL_DGROUP = "FAIL_DGROUP";
  public static final String SUCCESS_DGROUP = "SUCCESS_DGROUP";
  public static final String FAIL_ADD_USER_TO_GROUP = "FAIL_ADD_USER_TO_GROUP";
  public static final String SUCCESS_ADD_USER_TO_GROUP = "SUCCESS_ADD_USER_TO_GROUP";
  public static final String FAIL_DELETE_USER_FROM_GROUP = "FAIL_DELETE_USER_FROM_GROUP";
  public static final String SUCCESS_DELETE_USER_FROM_GROUP = "SUCCESS_DELETE_USER_FROM_GROUP";
  public static final String FAIL_LIST_MEMBERS = "FAIL_LIST_MEMBERS";
  public static final String SUCCESS_LIST_MEMBERS = "SUCCESS_LIST_MEMBERS";
  public static final String FAIL_CONNECT = "FAIL_CONNECT";
  public static final String SUCCESS_CONNECT = "SUCCESS_CONNECT";
  public static final String FAIL_KEY = "FAIL_KEY";
  public static final String SUCCESS_KEY = "SUCCESS_KEY";
  public static final String FAIL_GKEY = "FAIL_GET_KEY";
  public static final String SUCCESS_GKEY = "SUCCESS_GET_KEY";
  

  // generic error for lack of admin permissions
  public static final String FAIL_NO_ADMIN_MSG = "You must be an admin to perform that action.\nPlease obtain an admin token and try again.";

  // generic error for requester with a bad token
  public static final String FAIL_BAD_TOKEN_MSG = "You must obtain a valid token to perform this action.";

  // generic error for when requester is not the owner of a group
  public static final String FAIL_NO_OWNER_MSG = "You must be the owner of the group to perform this action.";

  // generic errors for when user or group already exist
  public static final String FAIL_USER_EXIST_MSG = "That user already exists.";
  public static final String FAIL_GROUP_EXIST_MSG = "That group already exists.";

  // generic errors for when user or group does not exist
  public static final String FAIL_USER_NO_EXIST_MSG = "That user does not exist.";
  public static final String FAIL_GROUP_NO_EXIST_MSG = "That group does not exist.";

  // generic errors for when user is or is not already a member of a group
  public static final String FAIL_MEMBER_MSG = "That user is already a member of that group.";
  public static final String FAIL_NO_MEMBER_MSG = "That use is not a member of that group.";

  // GroupClient.getToken
  public static final String FAIL_GET_MSG = "An error occurred while obtaining a token.";
  public static final String SUCCESS_GET_MSG = "Token obtained successfully.";


  // GroupClient.createUser
  public static final String FAIL_CUSER_MSG = "An error occurred while creating this user.";
  public static final String SUCCESS_CUSER_MSG = "User created successfully.";

  // GroupClient.deleteUser
  public static final String FAIL_DUSER_MSG = "An error occurred while deleting this user.";
  public static final String SUCCESS_DUSER_MSG = "User deleted successfully.";

  // GroupClient.createGroup
  public static final String FAIL_CGROUP_MSG = "An error occurred while creating this group.";
  public static final String SUCCESS_CGROUP_MSG = "Group successfully created.";

  // GroupClient.deleteGroup
  public static final String FAIL_DGROUP_MSG = "An error occurred while deleting this group.";
  public static final String SUCCESS_DGROUP_MSG = "Group successfully deleted.";

  // GroupClient.addUserToGroup
  public static final String FAIL_ADD_USER_TO_GROUP_MSG = "An error occurred while adding this user to the group.";
  public static final String SUCCESS_ADD_USER_TO_GROUP_MSG = "User successfully added to group.";

  // GroupClient.removeUserFromGroup
  public static final String FAIL_DELETE_USER_FROM_GROUP_MSG = "An error occurred while deleting this user from the group.";
  public static final String SUCCESS_DELETE_USER_FROM_GROUP_MSG = "User successfully deleted from group.";

  // GroupClient.listMembers
  public static final String FAIL_LIST_MEMBERS_MSG = "An error occurred while fetching the members of this group.";
  public static final String SUCCESS_LIST_MEMBERS_MSG = "Successfully fetched members of this group.";

  // for when the client attempts to connect to the server
  public static final String FAIL_CONNECT_MSG = "An error occurred while connecting to the server.";
  public static final String SUCCESS_CONNECT_MSG = "Secure connection to the server established.";
  
  //GroupClient.getTokenSignature
  public static final String FAIL_SIGNTOKEN_MSG = "An error occurred while signing the token.";
  public static final String SUCCESS_SIGNTOKEN_MSG = "Token signed successfully.";
 
  // GroupClient.getKey
  public static final String FAIL_GET_KEY_MSG = "An error occured when trying to grab the key.";
  public static final String SUCCESS_GET_KEY_MSG = "Success retrieving key";

  public static HashMap<String,Integer> s = new HashMap<String,Integer>();


  public static int getIntForString(String responseType)
  {
    s.put("FAIL_NO_ADMIN",1 );
    s.put("FAIL_BAD_TOKEN",2);
    s.put("FAIL_NO_OWNER",3);
    s.put("FAIL_USER_EXIST",4);
    s.put("FAIL_GROUP_EXIST",5);
    s.put("FAIL_USER_NO_EXIST",6);
    s.put("FAIL_GROUP_NO_EXIST",7);
    s.put("FAIL_MEMBER",8);
    s.put("FAIL_NO_MEMBER",9);
    s.put("FAIL_GET",10);
    s.put("SUCCESS_GET",11);
    s.put("FAIL_CUSER",12);
    s.put("SUCCESS_CUSER",13);
    s.put("FAIL_DUSER",14);
    s.put("SUCCESS_DUSER",15);
    s.put("FAIL_CGROUP",16);
    s.put("SUCCESS_CGROUP",17);
    s.put("FAIL_DGROUP",18);
    s.put("SUCCESS_DGROUP",19);
    s.put("FAIL_ADD_USER_TO_GROUP",20);
    s.put("SUCCESS_ADD_USER_TO_GROUP",21);
    s.put("FAIL_DELETE_USER_FROM_GROUP",22);
    s.put("SUCCESS_DELETE_USER_FROM_GROUP",23);
    s.put("FAIL_LIST_MEMBERS",24);
    s.put("SUCCESS_LIST_MEMBERS",25);
    s.put("FAIL_CONNECT", 26);
    s.put("SUCCESS_CONNECT", 27);
    s.put("SUCCESS_SIGNTOKEN", 28);
    s.put("FAIL_SIGNTOKEN", 29);
    s.put("FAIL_GET_KEY", 30);
    s.put("SUCCESS_GET_KEY", 31);
    return s.get(responseType);

  }

  // method to get error type that corresponds to each error message
  public static String responseTypeToMessage(String responseType) {
    switch (getIntForString(responseType)) {
      case 1: return FAIL_NO_ADMIN_MSG;
      case 2: return FAIL_BAD_TOKEN_MSG;
      case 3: return FAIL_NO_OWNER_MSG;
      case 4: return FAIL_USER_EXIST_MSG;
      case 5: return FAIL_GROUP_EXIST_MSG;
      case 6: return FAIL_USER_NO_EXIST_MSG;
      case 7: return FAIL_GROUP_NO_EXIST_MSG;
      case 8: return FAIL_MEMBER_MSG;
      case 9: return FAIL_NO_MEMBER_MSG;
      case 10: return FAIL_GET_MSG;
      case 11: return SUCCESS_GET_MSG;
      case 12: return FAIL_CUSER_MSG;
      case 13: return SUCCESS_CUSER_MSG;
      case 14: return FAIL_DUSER_MSG;
      case 15: return SUCCESS_DUSER_MSG;
      case 16: return FAIL_CGROUP_MSG;
      case 17: return SUCCESS_CGROUP_MSG;
      case 18: return FAIL_DGROUP_MSG;
      case 19: return SUCCESS_DGROUP_MSG;
      case 20: return FAIL_ADD_USER_TO_GROUP_MSG;
      case 21: return SUCCESS_ADD_USER_TO_GROUP_MSG;
      case 22: return FAIL_DELETE_USER_FROM_GROUP_MSG;
      case 23: return SUCCESS_DELETE_USER_FROM_GROUP_MSG;
      case 24: return FAIL_LIST_MEMBERS_MSG;
      case 25: return SUCCESS_LIST_MEMBERS_MSG;
      case 26: return FAIL_CONNECT_MSG;
      case 27: return SUCCESS_CONNECT_MSG;
      case 28: return SUCCESS_SIGNTOKEN_MSG;
      case 29: return FAIL_SIGNTOKEN_MSG;
      case 30: return FAIL_GET_KEY_MSG;
      case 31: return SUCCESS_GET_KEY_MSG;
      default: return "";
    }
  }
}
