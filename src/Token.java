import java.util.*;
import java.security.Signature;
import java.security.*;
import javax.crypto.*;

import java.lang.StringBuilder;
import java.security.SecureRandom;
import java.security.Signature;
/*
An implementation of the UserToken interface. This class will be used to
encapsulate the data associated with a particular user token which will be
issued by a GroupServer and can be used to authenticate a particular user.
*/

public class Token implements UserToken, java.io.Serializable
{
  private String issuer;
  private String subject;
  private List<String> groups;
  private String fs_ip;
  private int fs_port;
  private byte[] signature;
  final String delimiter = "||";
  public Token(String server, String user, List<String> groupList, String fs_ip, int fs_port) 
  {
    this.issuer = new String(server);
    this.subject = new String(user);
    this.groups = new ArrayList<String>(groupList);
    this.fs_ip = fs_ip;
    this.fs_port = fs_port;
  }

  /**
  * Method to return the name of the group server that issued this token.
  * @return the issuer of this token
  */
  public String getIssuer()
  {
    return new String(this.issuer);
  }

  /**
  * Method to return the name of the user associated with this token.
  * @return the subject of this token
  */
  public String getSubject()
  {
    return new String(this.subject);
  }

  /**
  * Method to return the list of groups that the subject of this token should
  * have access to.
  * @return the groups that this token has access to
  */
  public List<String> getGroups()
  {
    return new ArrayList<String>(this.groups);
  }

  public void setSignature(PrivateKey privateKey) throws Exception
  {
    this.signature = getTokenSignature(privateKey);
  }

  public byte[] getSignature() throws Exception
  {
    return this.signature;
  }

  public byte[] getTokenSignature(PrivateKey privateKey) throws Exception 
  {
    String tokenStr = getTokenString();
    byte[] tokenStrBytes = tokenStr.getBytes();
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(tokenStrBytes);
    return signature.sign();
  }

  public String getTokenString() 
  {
    StringBuilder tokenStr = new StringBuilder();

    tokenStr.append(this.getIssuer());
    tokenStr.append(delimiter);
    tokenStr.append(this.getSubject());
    tokenStr.append(delimiter);

    for (int i = 0; i < this.getGroups().size(); i++) {
      tokenStr.append(this.getGroups().get(i));
      tokenStr.append(delimiter);
    }

    tokenStr.append(this.getFS_IP());
    tokenStr.append(delimiter);
    tokenStr.append(this.getFS_port());
    return tokenStr.toString();
  }

  public String getFS_IP() {
    return this.fs_ip;
  }

  public int getFS_port() {
    return this.fs_port;
  }
}
