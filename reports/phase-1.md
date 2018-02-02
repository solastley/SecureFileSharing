# CS 1653 Project Phase 1
## Group Info:
Contributor_1 = {
	Name: Alex Mesko,
	PittID: ALM336,
	GithubID: Skysaw144
}
Contributor_2 = {
	Name: John Fahnestock,
	PittID: JDF66,
	GithubID: Johnfcs778
}
Contributor_3 = {
	Name: Solomon Astley,
	PittID: SSA35,
	GithubID: Solastley
}

### Security Properties.

- Property 1: Credentials. Only users with an acceptable username and password will be granted any access to the file sharing system. If a user is not listed as either a professor at the university or a trusted system administrator, they will not be allowed to connect to the servers. This prevents users without valid credentials (students) from accessing the servers.

- Property 2: Uniqueness. Both group names and usernames within the file sharing system will necessarily be unique. If someone attempts to create/modify a group name or username such that it is the same as an existing, respective group name or username, they will not be permitted to do so. This is an attempt to prevent potential vulnerabilities in the system which would allow a user to access a group or files which they do not have permissions for.

- Property 3: No Default Permissions. By default, all non-admin users will initially not have any permissions for groups or files within the file sharing system. In order to gain access to a group or a file within a group, users must be explicitly granted permission by a user within the group. This prevents the accidental assignment of extra permissions to users by default.

- Property 4: Limited Visibility. This property states that a user shall only be able to see the existence of a group (and therefore files within that group) if they are a member of the group. If a user attempts to view the groups or files within a group on the file server, they will only be shown groups (and files within those groups) of which they are a member. This prevents users from knowing the names of groups and locations of files to which they do not have access.

- Property 5: Group Permissions. This property states that a user shall only be able to create/delete a group if they have the proper permissions to do so. If a user attempts to create a group, they must have the proper general permissions to create groups on the file server. If a user attempts to delete a group, they must have the proper specific permissions to delete that particular group. In particular for a group, only the creator of the group or a system admin should have permission to delete the group. This prevents untrusted users from being able to arbitrarily create new groups and delete existing groups on the server.

- Property 6: Encryption. This property states that all communication between client applications and the servers will be encrypted. This prevents attackers from gaining access to file/group data by listening to the communication channel.

- Property 7: Private User Credentials. This property states that all user-authentication data (such as usernames and passwords) will be stored in a secure fashion. In particular, as opposed to storing plaintext versions of usernames and passwords on a server, the system will store hashed versions of usernames and passwords. This will prevent attackers from gaining access to user data even in the case that the user authentication data is compromised.

- Property 8: Group Limits. This property states that users will be limited in the number of groups that they may create. In particular, some maximum number of groups will be chosen so that users may create a reasonable number of groups. This prevents users from creating an arbitrary number of groups in order to hog server resources and deny service to other users.

- Property 9: Memory Limits. This property states that groups will be limited in the amount of memory they are allocated for file storage within the group. In particular, some maximum amount of memory will initially allowed, and any additional memory will need to be explicitly requested from a trusted system admin. This prevents users within a group from using an arbitrary amount of memory for file storage in order to hog server resources and deny service to other users.

- Property 10: Certified devices only. To circumvent imposters from attempting to login as an accepted user with accepted credentials, a list of a user’s certified devices will be maintained. Each user will be granted some set number of devices (e.g.: 3, 5, etc) as set by the sysadmin. In order for a new device to be registered for a user, a ticket must be securely submitted to the sysadmin with the prospective device’s credentials for approval. Submission of these credentials is only permitted from a currently trusted source for a user, and a second factor of authentication will be required to submit the ticket to ensure the request is genuine.

- Property 11: Content Integrity. This property states that each time a file is modified, it will be stamped with a unique signature generated using a hash of its contents. In order to verify that a file has not been tampered with, users may generate a hash of the file’s contents and compare it to the last known, verified hash of the file. This allows users to determine if an attacker has tampered with a file without permission.

- Property 12: Modification History. In order to implement this property, a log will be kept, unique to each group, which will keep record of all additions/deletions/or modifications to files within the group. This log will be automatically updated and each user within the group will have access to view the log, but not change it directly.

- Property 13: Login Attempt Cooldown. This property will implement a restriction on the amount of login attempts within a certain period of time for a single user. If too many failed login attempts occur from a device for a certain username, that device will be temporarily locked out of logging into the group server. This will protect against non-human brute force login attempts.

- Property 14: User Permission Levels. Each user within a group will have a certain permission level that is dictated by the sysadmin. For example, some users may only be able to read files, others can read/write, others can read/write/delete etc.

- Property 15: Two-step Group Additions. In order for a user to join a group, they will have to first know the name of the group they are attempting to join and will submit a request to the server stating that user u wants to join group g. The sysAdmin for the group will have to accept this request, and then that user will be granted permissions for that group.

- Property 16: Use SSH for auth. In order to ensure secure connection to the server each user could be required to generate ssh keys and upload their public key to the server. The group would use ssh for client requests.

- Property 17: Block Certain Traffic With A Firewall. Have a basic firewall on the server that will block all ports except ones necessary. For example, the standard ports for SSH and FTP would remain open to allow for authentication and file transfers, but the ports for HTTP and telnet would be blocked.

- Property 18: Intrusion Detection System. Implement an IDS on the server that will monitor traffic and look for suspicious activity/intrusion attempts and will report any of this activity to the sysadmin. This will work in conjunction with the firewall where the firewall looks to prevent this sort of activity, the IDS will detect and report this activity if it takes place. For example, if a user uploads a malicious exe to the group files, the IDS may be able to detect and report this.

- Property 19: Specific Options Per File. When a file is added to the server, whichever user is the author of the file, can specify if that file is to be read only to the rest of the users in that group. This is so that a user can upload a file for everyone else to see and download but not edit if there could be a chance for a malicious edit to the file by another user.

- Property 20: Server File Visibility.  Ensure that on a group server, the users for that server can only see the files that are within the specified directory. For example, on the machine that is the group server, when a user connects they are not shown or given access to every file on that system, only the subdirectory that contains the shared files they are supposed to be able to see.

### Threat Models
#### Threat Model 1: A Group File-Sharing System for Professors
The system will be deployed on a server within a university LAN. The servers will be accessible by anyone connected to the LAN. The LAN is connected to the Internet, however it is assumed that it is protected by a firewall and thus only students and professors will have access to the LAN.

The servers should only be available to professors with a proper university username and password. Additionally, it is assumed that the university has at least one trusted system administrator with the proper permissions to access/modify the servers.

##### Relevant Security Properties
- Property 1: Credentials. With the exception of a system admin, only professors with a valid username and password may access the system.

- Property 2: Uniqueness. This is an attempt to prevent potential vulnerabilities in the system which would allow a user to access a group or files which they do not have permissions for.

- Property 3: No Default Permissions. By default, users will not have access to any groups. They must be added to the group by an existing member.

- Property 4: Limited Visibility. Professors' exposure to existing groups will be limited to the groups in which they are currently members.

- Property 5: Group Permissions. Professors should not be allowed to arbitrarily create or delete groups.

- Property 6: Encryption. Encrypted communication between clients and servers will help thwart potential attackers (students or otherwise) from accessing plain text data by listening to the communication medium.

- Property 7: Private User Credentials. This will prevent attackers from accessing professors' user credentials if the authorization files are compromised. This is especially important for this threat model because professor credentials could be used to access various other university resources which should be secure.

- Property 8: Group Limits. Professors should not allowed to make an arbitrary number of groups.

- Property 9: Memory Limits. Professors should not be allowed to use an arbitrary amount of system memory, potentially denying service to other users.

- Property 10: Certified Devices Only. Two-factor authentication should be employed as an additional level of authenticating users. This serves as a backup authentication technique in the case that professor usernames and passwords are compromised in some way.

- Property 13: Login Attempt Cooldown. This property ensures that authentication cannot be achieved by brute-force methods.

- Property 14: User Permission Levels. Professors will only be able to read/update/upload/delete files if they have the proper types of permissions.

- Property 15: Two-Step Group Additions. This property helps ensure that users only attempt to join groups which they ordinarily should have knowledge of/access to.

- Property 18: Intrustion Detection System. This property helps prevent users from uploading malicious files to the system.

- Property 19: Specific Options Per File. Owners of files should designate what types of operations that other users may perform on the files.

- Property 20: Server File Visibility. This helps to ensure that users only have access to the files owned by groups of which they are a member.

#### Threat Model 2: A Remote File Sharing System for Organizations
A trusted site is utilized to host code for organizations (similar to GitHub). The initial repository must be granted by the site to the user (group owner) who created it. After this first user, invitations must be sent to additional potential contributors from this group’s owner. Code will be pushed/pulled via a user’s computer terminal after they have proven they are authorized to access content of a given repo.

##### Relevant Security Properties
- Property 1: Credentials. A repo may only be changed upon an accepted contributor to said repo correctly entering the password associated with said user.

- Property 2: Uniqueness. Similar to GitHub in that you cannot have to addresses map to the same repo as there would be a conflict. For example, suppose there exists a repo named "XYZRepo"; now suppose duplicate names were permitted of repos such that some arbitrary additional instances of repos named "XYZRepo" were permitted. When a contributor to any of these repos attempts to clone into their repo(a la git CLI) there would be a conflict as to which repo they actually have privilege. For this reason, repo naming uniqueness must be enforced.

- Property 3: No Default Permissions. Each repo will be essentially private, as such the only way one may become a contributor to the repo is if they are invited to join the repo by the repo's owner. Furthermore, permissions per group contributor can be modified as the group owner sees suitable(think read/write permissions on a UNIX system).

- Propert 5: Group Permissions. Only the owner of a given repo may delete a given repo. Contributors are just that, contributors. There is no mechanism by which a repo contributor will be granted permission to delete a relevant repo.

- Property 6: Encryption. As this threat model details a source control system, it is necessary that all code transmitted by it be encrypted to prevent the loss/theft of some properietary software which could be leveraged against users or the hosting party(e.g. GitHub). Furthermore, data stored on the host's servers should be encrypted in a manner such that only a group's private key may decrypt it to reduce incentive of theft should an attacker have physical access to the hosting site's network.

- Property 7: Private User Credentials. This property aims to mitigate possible damage done by an attacker who has gained access to the hosting site's database of usernames & passwords. Because user credentials will be hashed before they are stored, it should not be computationally feasible to determine username/password pairs without the function used to compute the hash. 

- Property 8: Group Limits. There is not infinite server space provided by the host, so a reasonable limit of active repos should be imposed upon registered parties utilizing the host's services.

- Property 9: Memory Limits. Similar to the above requirement. 

- Property 10: Certified Devices Only. The host will enforce a policy that only devices proven to be in possession of currently accepted group owners & contributors will be permitted to access/alter their source code. If a group owner or contributor wishes to add a device, the host will issue a challenge to the user requiring successful submission of a 2nd factor token(e.g. Authy's generation of tokens for services providing two-factor authenication). To narrow the threat surface, users will not be permitted to add an unbounded number of devices. A reasonable accommodation seems to be ~3 devices per user.

- Property 12: Modification History. For a site hosting code, it is necessary to keep track of modificaations to all filesm this could be like a simple record of commits. 

- Property 14: User Permission Levels. This is relevant for a online code repo since within a company certain employees may be able to push to a certain branch where others may not be able to push to that branch.

- Property 16: Use SSH for auth. A secure system for connecting to the remote server is always beneficial especially in the case of a repository for a company or business. 

- Property 19: Specific Options Per File. This can be useful in this threat model if for example someone creates a header file for a project acting as a sort of database that should not be altered except by the creator, they can set it to read only for the rest of the users.
