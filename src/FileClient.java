/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.util.List;
import java.security.*;

public class FileClient extends Client implements FileClientInterface {

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		env.addObject(remotePath);
		env.addObject(token);

		encryptAndWriteMessage(env);
		env = readAndDecryptResponse();

		if (isValidMessage(env, 1)) {
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {
			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				Envelope env = new Envelope("DOWNLOADF"); //Success
				env.addObject(sourceFile);
				env.addObject(token);
				encryptAndWriteMessage(env);

				env = readAndDecryptResponse();

				while (env.getMessage().compareTo("CHUNK")==0) {
					fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					encryptAndWriteMessage(env);
					env = readAndDecryptResponse();
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					encryptAndWriteMessage(env);
				}
				else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}


		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;


		}

		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		try
		{
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(token); //Add requester's token
			encryptAndWriteMessage(message);

			e = readAndDecryptResponse();

			//If server indicates success, return the member list
			if(e.getMessage().equals("OK"))
			{
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean upload(String sourceFile, String destFile, String group,
	UserToken token) {

		if (destFile.charAt(0)!='/') {
			destFile = "/" + destFile;
		}

		try
		{

			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); //Add requester's token
			encryptAndWriteMessage(message);


			FileInputStream fis = new FileInputStream(sourceFile);

			env = readAndDecryptResponse();

			//If server indicates success, return the member list
			if(env.getMessage().equals("READY"))
			{
				System.out.printf("Meta data upload successful\n");

			}
			else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}


			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY")!=0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); //can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				message.addObject(buf);
				message.addObject(new Integer(n));

				encryptAndWriteMessage(message);


				env = readAndDecryptResponse();


			}
			while (fis.available()>0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY")==0)
			{

				message = new Envelope("EOF");
				encryptAndWriteMessage(message);

				env = readAndDecryptResponse();
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			}
			else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		}catch(Exception e1)
		{
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}
}
