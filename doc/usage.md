# Usage Instructions

## Configuration
Within the `Makefile`, you should set values for the IP address and port number of the group and file servers. These values will be used by both servers and clients when they are run. The servers will use the port numbers to determine which port to listen on and the client will use the IP addresses and port numbers to determine how to connect to the group and file servers.

The following properties should be configured within `Makefile`:
 - GS_IP: The IP address of the machine that the group server is running on
 - GS_PORT: The port number that the group server will listen on
 - FS_IP: The IP address of the machine that the file server is running on
 - FS_PORT: The port number that the file server will listen on

## Starting the Group Server

To start the group server, simply run `make gs`.

When the group server is first started, there are no users or groups. Since there must be an administrator of the system, the user is prompted via the console to enter a username and password. This name becomes the first user and is a member of the **ADMIN** group.  No groups other than **ADMIN** will exist at first.

## Starting the File Server

To start the file server, simply run `make fs`.

The file server will create a `shared_files` directory if one does not exist.

## Starting the Client Application

To start the client application, simply run `make client`.

## Resetting the Group or File Server

You may want to reset the groups, users, or files on the group and file servers.

To remove all existing groups and users from the group server, run `make clean_gs`.

To remove all existing files from the file server, run `make clean_fs`.

To remove all existing groups, users, and files from both servers, run `make clean_both`.
