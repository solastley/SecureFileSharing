# file and group server configurations
GS_IP=127.0.0.1
GS_PORT=8765
FS_IP=127.0.0.1
FS_PORT=8766


# java
JC=javac
J=java

# JAR files (can be overridden at command line)
CP?=lib/*

# output directory for compiled java class files (can be overridden at command line)
OUTPUT_DIR?=build

# Java source file directory
SRC_DIR=src

# names of files containing main methods
GROUP_SERVER=RunGroupServer
FILE_SERVER=RunFileServer
CLIENT=MyClientApp

# default to compile
default: compile

# rule to compile the Java files
compile:
	# make output directory unless it exists
	test -d $(OUTPUT_DIR) || mkdir $(OUTPUT_DIR)
	# compile Java files
	$(JC) -d $(OUTPUT_DIR) -cp $(CP) $(SRC_DIR)/*.java

# rule to clean old class files
clean:
	rm -f $(OUTPUT_DIR)/*.class

# rule to run the group server
gs: compile
	$(J) -cp $(OUTPUT_DIR):$(CP) $(GROUP_SERVER) $(GS_PORT)

# rule to run the file server
fs: compile
	$(J) -cp $(OUTPUT_DIR):$(CP) $(FILE_SERVER) $(FS_PORT)

# rule to run the client application
client: compile
	$(J) -cp $(OUTPUT_DIR):$(CP) $(CLIENT) $(GS_IP) $(GS_PORT) $(FS_IP) $(FS_PORT) 

# rule to remove existing groups and users
clean_gs:
	rm -f GroupList.bin
	rm -f UserList.bin
	rm -f KeyList.bin

# rule to remove existing files
clean_fs:
	rm -f FileList.bin
	rm -rf shared_files/

# rule to remove existing groups, users, and files
clean_both: clean_gs clean_fs
