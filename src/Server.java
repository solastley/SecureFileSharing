import java.net.Socket;
import java.io.*;
import java.security.*;
import javax.crypto.*;

public abstract class Server {

	protected int port;
	public String name;

	// RSA keys
	public PublicKey publicKey;
	private PrivateKey privateKey;

	// this needs to be long enough to encrypt a sufficiently long AES key
	private static final int RSA_KEY_SIZE = 4096;

	abstract void start();

	public Server(int _SERVER_PORT, String _serverName) {
		port = _SERVER_PORT;
		name = _serverName;
	}

	public int getPort() {
		return port;
	}

	public String getName() {
		return name;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	* This method reads the RSA keys for this server from disk. If the key files
	* do not exist, it generates new RSA keys and writes them to files.
	* @param publicKeyFileName the name of the file containing the public RSA key
	* @param privateKeyFileName the name of the file containing the private RSA key
	*/
	public void generateKeys(String publicKeyFileName, String privateKeyFileName) {
		// try to read RSA keys from file
		File privateKeyFile = new File(privateKeyFileName);
		File publicKeyFile = new File(publicKeyFileName);
		try {
			if (privateKeyFile.exists() && publicKeyFile.exists()) {
				// read private key
				ObjectInputStream keyReader = new ObjectInputStream(new FileInputStream(privateKeyFile));
				privateKey = (PrivateKey) keyReader.readObject();

				// read public key
				keyReader = new ObjectInputStream(new FileInputStream(publicKeyFile));
				publicKey = (PublicKey) keyReader.readObject();
			} else {
				// keys do not exist, generate them now
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(RSA_KEY_SIZE);
				KeyPair keyPair = keyGen.generateKeyPair();
				privateKey = keyPair.getPrivate();
				publicKey = keyPair.getPublic();

				// write keys to disk
				ObjectOutputStream keyWriter = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
				keyWriter.writeObject(privateKey);
				keyWriter.close();
				keyWriter = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
				keyWriter.writeObject(publicKey);
				keyWriter.close();
			}
		} catch (Exception e) {
			System.err.println("Error while reading or generating RSA keys.");
			System.exit(1);
		}
	}

	/**
	* This method is used to check the authenticity of a user's token.
	* @param token the token to be checked
	* @return true if the token is authentic, false otherwise
	*/
	public boolean validateToken(UserToken token) {
		// TODO: implement this method after adding signature property to tokens
		if (token != null) {
			return true;
		}

		return false;
	}
}
