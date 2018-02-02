/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.security.*;
import java.security.Signature;
import java.lang.StringBuilder;


public class FileThread extends ServerThread
{
	private final Socket socket;
	private final FileServer server;

	public FileThread(Socket _socket, FileServer _server)
	{
		socket = _socket;
		server = _server;
		privateKey = server.getPrivateKey();
		publicKey = server.getPublicKey();

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
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

			// confirm public key with client
			if (!establishPublicKey()) {
				System.err.println("Error occurred while attempting to establish public key.");
				return;
			}

			// establish session key with client
			if (!establishSessionKey()) {
				System.err.println("Error occurred while attempting to establish session key.");
				return;
			}

			do
			{
				message = readAndDecryptMessage();
				System.out.println("Request received: " + message.getMessage());

				// Handler to list files that this user is allowed to see
				if(message.getMessage().equals("LFILES"))
				{
					response = new Envelope("FAIL-BADTOKEN");

					if (isValidMessage(message, 2)) {
						List<String> userFiles = new ArrayList<String>();

						// get the groups for this user
						UserToken yourToken = (UserToken) message.getObjContents().get(0);

						if (!verifyTokenSignature(yourToken)) {
							System.err.println("TOKEN SIGNATURE NOT VALID");
							System.exit(1);
						} 
						
						List<String> userGroups = yourToken.getGroups();

						// iterate through user's groups
						Iterator<String> groupIter = userGroups.iterator();
						while (groupIter.hasNext())
						{
							// get the files for this group
							List<ShareFile> groupFiles = server.fileList.getFilesForGroup((String) groupIter.next());

							// add each of the files for this group to userFiles
							Iterator<ShareFile> fileIter = groupFiles.iterator();
							while (fileIter.hasNext())
							{
								ShareFile nextFile = (ShareFile) fileIter.next();
								userFiles.add(nextFile.getPath());
							}
						}

						response = new Envelope("OK");
						response.addObject(userFiles);
					}

					encryptAndWriteResponse(response);
				}
				if(message.getMessage().equals("UPLOADF"))
				{
					response = new Envelope("FAIL-BADCONTENTS");

					if(message.getObjContents().size() == 4)
					{
						if(message.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						else if (message.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						else if (message.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)message.getObjContents().get(0);
							String group = (String)message.getObjContents().get(1);
							UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract token
							// verifyTokenSignature(yourToken);

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								encryptAndWriteResponse(response);

								message = readAndDecryptMessage();
								while (message.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])message.getObjContents().get(0), 0, (Integer)message.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									encryptAndWriteResponse(response);
									message = readAndDecryptMessage();
								}

								if(message.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					encryptAndWriteResponse(response);
				}
				else if (message.getMessage().compareTo("DOWNLOADF")==0)
				{
					if (isValidMessage(message, 3)) {
						String remotePath = (String)message.getObjContents().get(0);
						Token t = (Token)message.getObjContents().get(1);
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							response = new Envelope("ERROR_FILEMISSING");
							encryptAndWriteResponse(response);
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							response = new Envelope("ERROR_PERMISSION");
							encryptAndWriteResponse(response);
						}
						else {

							try
							{
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									response = new Envelope("ERROR_NOTONDISK");
									encryptAndWriteResponse(response);
								}
								else {
									FileInputStream fis = new FileInputStream(f);

									do {
										byte[] buf = new byte[4096];
										if (message.getMessage().compareTo("DOWNLOADF")!=0) {
											System.out.printf("Server error: %s\n", message.getMessage());
											break;
										}
										response = new Envelope("CHUNK");
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) {
											System.out.printf(".");
										} else if (n < 0) {
											System.out.println("Read error");

										}

										response.addObject(buf);
										response.addObject(new Integer(n));

										encryptAndWriteResponse(response);

										message = readAndDecryptMessage();
									}
									while (fis.available()>0);

									//If server indicates success, return the member list
									if(message.getMessage().compareTo("DOWNLOADF")==0)
									{
										response = new Envelope("EOF");
										encryptAndWriteResponse(response);

										message = readAndDecryptMessage();
										if(message.getMessage().compareTo("OK")==0) {
											System.out.printf("File data upload successful\n");
										}
										else {
											System.out.printf("Upload failed: %s\n", message.getMessage());
										}
									}
									else {
										System.out.printf("Upload failed: %s\n", message.getMessage());
									}
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + message.getMessage());
								e1.printStackTrace(System.err);
							}
						}
					}
				}
				else if (message.getMessage().compareTo("DELETEF")==0)
				{
					if (isValidMessage(message, 3)) {
						String remotePath = (String)message.getObjContents().get(0);
						Token t = (Token)message.getObjContents().get(1);
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							response = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							response = new Envelope("ERROR_PERMISSION");
						}
						else {
							try
							{
								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									response = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									response = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									response = new Envelope("ERROR_DELETE");
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								response = new Envelope(e1.getMessage());
							}
						}
					}

					encryptAndWriteResponse(response);
				}
				else if(message.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + message.getMessage());
			e.printStackTrace(System.err);
		}
	}

	public boolean verifyTokenSignature(UserToken token) throws Exception {
		String gs = token.getIssuer();
		PublicKey publicKey = getGroupServerPublicKey();

		Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        byte[] tokenStringBytes = token.getTokenString().getBytes();
        signature.update(tokenStringBytes);

        return signature.verify(token.getSignature());
	}

	private PublicKey getGroupServerPublicKey() {
		try {
	      	ObjectInputStream keyReader = new ObjectInputStream(new FileInputStream(GroupServer.PUBLIC_KEY_FILE));
	      	PublicKey publicKey = (PublicKey) keyReader.readObject();
	      	keyReader.close();
	      	return publicKey;
	    } catch (Exception e) {
	    	System.err.println("Error while reading group server public key from disk.");
			System.exit(1);
	    }
	    return null;
	}
}
