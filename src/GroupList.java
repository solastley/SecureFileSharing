import java.util.*;

public class GroupList implements java.io.Serializable
{
	private static final long serialVersionUID = -3640596306597345734L;
	private ArrayList<String> groupList = new ArrayList<String>();

	public synchronized void addGroup(String groupname)
	{
		groupList.add(groupname);
	}

	public synchronized void removeGroup(String groupname)
	{
		groupList.remove(groupname);
	}

	public synchronized ArrayList<String> getGroupList()
	{
		return groupList;
	}

	public synchronized boolean hasGroup(String groupname)
	{
		if(groupList.contains(groupname))
		{
			return true;
		}
		else
		return false;
	}
}
