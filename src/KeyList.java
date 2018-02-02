import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;

import javax.crypto.*;
/*
 * This is a file the group server will maintain to keep track of the keys for certain groups 
 */
public class KeyList implements java.io.Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -4942600966661819036L;
	private HashMap<String, ArrayList<Key>> keyList = new HashMap<String,ArrayList<Key>>();
	protected final String AES_ALGORITHM = "AES";
	protected Key newKey;
	
	
	
	public synchronized void addGroupKey(String groupName) throws NoSuchAlgorithmException
	{
		KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
		newKey = keyGen.generateKey();
		// check to see if this group already has a key list
		if(!keyList.containsKey(groupName))
		{
			ArrayList<Key> keys = new ArrayList<Key>();
			keys.add(newKey);
			keyList.put(groupName, keys);
		}
		else
		{
			keyList.get(groupName).add(newKey);
		}
	}
	// If the user just wants the most recent key they will use -1 for the index
	public synchronized Key getKeyByIndex(String groupname, String index)
	{
		System.out.println(groupname);
		System.out.println(index);

		int index1 = Integer.valueOf(index);
		if(index1==-1)
		{ 
			int size = keyList.get(groupname).size();
			return keyList.get(groupname).get(size-1);
		}
		else
		{
			return keyList.get(groupname).get(index1);
		}
	}
}
