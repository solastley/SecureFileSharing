import java.net.Socket;
import java.io.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Scanner;

import java.security.*;
import javax.crypto.*;
import java.util.Arrays;

public abstract class Client {

	// for communicating with the server
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	// shared secret session key with server
	protected Key sessionKey;
	protected boolean sessionKeyEstablished = false;

	// separate key for signing messages
	protected Key signingKey;

	// public key of server to connect to
	protected PublicKey publicKey = null;

	private byte[] iv = new byte[16];

	// sequence number to prevent message reordering
	private int sequenceNumber = -1;

	// constants for encryption algorithms
	protected final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	protected final String SHA1_PRNG = "SHA1PRNG";
	protected final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
	protected final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
	protected final String AES_ALGORITHM = "AES";
	protected final String SHA_256_ALGORITHM = "SHA-256";

	/**
	* This method connects to the server and establishes a shared secret AES key
	* with the server according to the mechanism outlined in Protocol 1 of the
	* project writeup.
	* @param serverIP the IP address of the server to connect to
	* @param port the port number that the server is listening on
	* @return true if the connection and shared AES key are established
	*/
	public boolean connect(final String serverIP, final int port, boolean isFileServer) {
		System.out.println("Attempting to connect...");

		try {
			// connect to the server
			sock = new Socket(serverIP, port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());

			// the client is connecting to a file server, it must complete the protocol
			// to confirm the authenticity of the server's public key
			if (isFileServer && !verifyPublicKey(serverIP)) {
				return false;
			}

			// generate a random integer value and encrypt it
			SecureRandom random = SecureRandom.getInstance(SHA1_PRNG);
			Integer challenge = new Integer(random.nextInt());

			// generate AES session key
			KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
			sessionKey = keyGen.generateKey();

			// generate AES signing key
			signingKey = keyGen.generateKey();

			// construct message, encrypt it, and send it
			Envelope message = new Envelope("CONNECT");
			message.addObject(challenge);
			message.addObject(sessionKey);
			message.addObject(signingKey);
			encryptAndWriteMessage(message);
			sessionKeyEstablished = true;

			// read response from the server and decrypt it using server's public key
			Envelope response = readAndDecryptResponse();

			// check for successful response and incremented challenge
			if (response.getMessage().equals(ResponseConstants.SUCCESS_CONNECT)) {
				Integer challengeResponse = (Integer) response.getObjContents().get(0);
				if (challengeResponse.intValue() == challenge.intValue() + 1) {
					System.out.println(ResponseConstants.SUCCESS_CONNECT_MSG);
					return true;
				} else {
					System.out.println(ResponseConstants.FAIL_CONNECT_MSG);
				}
			}
		} catch (Exception e) {
			System.err.println("Connection error: " + e.getMessage());
		}

		sessionKeyEstablished = false;
		return false;
	}

	public boolean isConnected() {
		if (sock == null || sock.isClosed()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try {
				// send disconnect message to server
				Envelope message = new Envelope("DISCONNECT");
				encryptAndWriteMessage(message);

				// delete old session key
				sessionKey = null;
				sessionKeyEstablished = false;
				sequenceNumber = -1;

				// for some reason, even when the server calls socket.close(), a call
				// to sock.isConnected() still returns true in the client, so as a
				// temporary fix I added this - SA
				sock.close();
			} catch (Exception e) {
				System.err.println("Error closing the socket in Client.java");
			}
		}
	}

	/**
	* This method reads an encrypted Envelope from the server and returns
	* the decryption.
	*/
	public Envelope readAndDecryptResponse() {
		try {
			Envelope signedResponse = (Envelope) input.readObject();
			if (!verifySignature(signedResponse)) {
				throw new Exception("Invalid signature on the received message.");
			}
			SealedObject encryptedResponse = (SealedObject) signedResponse.getObjContents().get(0);
			Envelope response = (Envelope) decryptObject(encryptedResponse);

			int responseSize = response.getObjContents().size();
			int responseSequenceNumber = (Integer) response.getObjContents().get(responseSize - 1);
			if (sequenceNumber > 0 && responseSequenceNumber != sequenceNumber + 1) {
				throw new Exception("Invalid sequence number: " + responseSequenceNumber + ". Expecting: " + (sequenceNumber + 1));
			}

			sequenceNumber = responseSequenceNumber;
			return response;
		} catch (Exception e) {
			System.err.println("Error reading and decrypting response from server.");
			return null;
		}
	}

	/**
	* This method encrypts and sends an Envelope to the server.
	*/
	public void encryptAndWriteMessage(Envelope message) {
		// increment sequence number and add it to the message
    message.addObject(new Integer(++sequenceNumber));

    // encrypt the object in a SealedObject and send it
		try {
			SealedObject encryptedMessage = encryptObject(message);
			sendIV();

			if (sessionKeyEstablished) {
				Envelope signedMessage = signObject(encryptedMessage);
				output.writeObject(signedMessage);
			} else {
				output.writeObject(encryptedMessage);
			}
		} catch (Exception e) {
			System.err.println("Error encrypting and writing message to server.");
		}
	}

	/**
	* This method takes an Object and encrypts it using either the public
	* RSA key of the group server or the shared secret AES key for this client.
	* It uses javax.crypto.SealedObject to do this:
	* https://docs.oracle.com/javase/7/docs/api/javax/crypto/SealedObject.html
	* @param obj the object to encrypt
	* @return the encrypted SealedObject
	*/
	public SealedObject encryptObject(Serializable obj) {
		try {
			Cipher cipher = null;
			// if the shared AES key has been established
			if (sessionKeyEstablished) {
				// generate an IV for this current session
				generateIV();
				// generate and initialize an AES cipher
				cipher = Cipher.getInstance(AES_CBC_PKCS5);
				cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
			} else {
				// generate and initialize an RSA cipher
				cipher = Cipher.getInstance(RSA_ECB_PKCS1);
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			}

			return new SealedObject(obj, cipher);
		} catch (Exception e) {
			System.err.println("Error using AES or RSA algorithm for encryption.");
			System.err.println(e.getMessage());
			return null;
		}
	}

	/**
	* This method takes a SealedObject and decrypts it using either the private RSA key
	* of the group server or a shared secret AES key for this session.
	* @param sealedObj the object to decrypt
	* @return the decrypted object
	*/
	public Object decryptObject(SealedObject sealedObj) {
		try {
			Cipher cipher = null;
			// if the shared AES key has been established
			if (sessionKeyEstablished) {
				// generate and initialize an AES cipher
				cipher = Cipher.getInstance(AES_CBC_PKCS5);
				cipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
			} else {
				// generate and initialize an RSA cipher
				cipher = Cipher.getInstance(RSA_ECB_PKCS1);
				cipher.init(Cipher.DECRYPT_MODE, publicKey);
			}

			return sealedObj.getObject(cipher);
		} catch (Exception e) {
			System.err.println("Error using AES or RSA algorithm for decryption.");
			System.err.println(e.getMessage());
			return null;
		}
	}

	/**
   * This method signs a Java object for message integrity purposes. It does so
   * using an HMAC of a serialized version of the object using the SHA-1 algorithm
   * and a secret AES signing key.
   * @param obj the object to sign
   * @return the signed object
   */
  public Envelope signObject(SealedObject obj) {
    try {
      // generate an HMAC for the object
      String signature = getHMAC(obj);

      // encapsulate the old message and the signature in a new Envelope
      Envelope signedMessage = new Envelope("");
      signedMessage.addObject(obj);
      signedMessage.addObject(signature);

      return signedMessage;
    } catch (Exception e) {
      System.err.println("Error signing object: " + e.getMessage());
      return null;
    }
  }

  /**
   * This method generates an HMAC for an object.
   * @param obj the SealedObject to generate an HMAC for
   * @return the string represenation of the HMAC
   */
  public String getHMAC(SealedObject obj) {
    try {
      // generate an HMAC for the object
      byte[] objectData = serializeObject(obj);
      Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
      mac.init(signingKey);

      return toHexString(mac.doFinal(objectData));
    } catch (Exception e) {
      System.err.println("Error generating HMAC: " + e.getMessage());
      return null;
    }
  }

  /**
   * This method verifies the HMAC of a message.
   * @param message the Envelope containing a SealedObject and HMAC
   * @return true if the HMAC is valid
   */
  public boolean verifySignature(Envelope message) {
    try {
      SealedObject obj = (SealedObject) message.getObjContents().get(0);
      String signature = (String) message.getObjContents().get(1);

      // generate test HMAC for this message
      String testSignature = getHMAC(obj);

      // confirm the test matches the received HMAC
      return signature.equals(testSignature);
    } catch (Exception e) {
      System.err.println("Error in verifySignature: " + e.getMessage());
      return false;
    }
  }

  /**
   * This method serializes a Java object into a byte array.
   * @param obj the object to serialize
   * @return the serialized object
   */
  public byte[] serializeObject(Object obj) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ObjectOutputStream os = new ObjectOutputStream(out);
    os.writeObject(obj);

    return out.toByteArray();
  }

  /**
   * This method converts a byte array to a readable hex string.
   * @param bytes the byte array to convert
   * @return a readable hex representation of the byte array
   */
  public String toHexString(byte[] bytes) {
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < bytes.length; i++) {
      result.append(String.format("%02x", bytes[i]));
    }

    return result.toString();
  }

	/**
	 * This method generates a 16 byte IV required for AES encryption/decryption
	 */
	private void generateIV() {
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(iv);
	}

	/**
	 * This method sends the IV, byte by byte, to the listening server
	 */
	private void sendIV() {
		try {
			for (int i = 0; i < 16; i++) {
				output.writeObject(iv[i]);
			}
		} catch (Exception e) {
			System.err.println("Client: Error occured sending IV.");
		}
	}

	/**
	 * This method attempts to verify the public key of a file server when it is
	 * connected to for the first time. If the file server's public key has already
	 * been established, this method terminates early.
	 */
	private boolean verifyPublicKey(final String serverIP) {
		try {
			// read message from the server and check for errors
			Envelope keyMessage = (Envelope) input.readObject();

			// if the client has connected to this file server before, its authenticity
			// is already confirmed and we can skip the rest of this protocol
			if (publicKey != null) {
				Envelope keyResponse = new Envelope(ResponseConstants.SUCCESS_KEY);
				output.writeObject(keyResponse);

				return true;
			} else {
				// check for errors in the key message from the server
				if (keyMessage.getObjContents().size() != 1 || keyMessage.getObjContents().get(0) == null) {
					System.out.println("Error occurred while requesting public key from the file server.");
					Envelope keyResponse = new Envelope(ResponseConstants.FAIL_KEY);
					output.writeObject(keyResponse);
					return false;
				}

				// get the key and generate a fingerprint
				PublicKey newKey = (PublicKey) keyMessage.getObjContents().get(0);
				byte[] newKeyBytes = newKey.getEncoded();
				MessageDigest md = MessageDigest.getInstance(SHA_256_ALGORITHM);
				byte[] digest = md.digest(newKeyBytes);

				// convert fingerprint to readable string for the user
				StringBuilder b = new StringBuilder("SHA256:");
				for (int i = 0; i < digest.length; i++) {
					b.append(Integer.toString((digest[i] & 0xff) + 0x100, 16).substring(1));
				}
				String newKeyFingerprint = b.toString();

				// present the key fingerprint to the user
				System.out.println("The authenticity of host " + serverIP + " cannot be established.");
				System.out.println("RSA key fingerprint is " + newKeyFingerprint);
				System.out.print("Are you sure you want to continue connecting (yes/no)? ");

				// get user response
				Scanner inScan = new Scanner(System.in);
				String response = inScan.nextLine();
				if (response.toLowerCase().equals("yes") || response.toLowerCase().equals("y")) {
					System.out.println("Warning - permanently added " + serverIP + " to the list of known hosts.");
					publicKey = newKey;
					Envelope keyResponse = new Envelope(ResponseConstants.SUCCESS_KEY);
					output.writeObject(keyResponse);

					return true;
				} else {
					System.out.println("Host key verification failed.");
					Envelope keyResponse = new Envelope(ResponseConstants.FAIL_KEY);
					output.writeObject(keyResponse);

					return false;
				}
			}
		} catch (Exception e) {
			System.err.println("Error occurred while verifying public key: " + e.getMessage());
			return false;
		}
	}

	/**
	 * This method checks if a client message is valid. It checks for the existence
	 * of the required objects in the message.
	 * @param message the message to verify
	 * @param expectedMessageSize the number of objects expected in this message
	 * @return true if the response is valid
	 */
	public boolean isValidMessage(Envelope message, int expectedMessageSize) {
		if (message.getObjContents().size() != expectedMessageSize) {
			return false;
		}

		for (int i = 0; i < expectedMessageSize; i++) {
			if (message.getObjContents().get(i) == null) {
				return false;
			}
		}

		return true;
	}
}
