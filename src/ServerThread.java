/**
* This class is a simple extension of the Java Thread class. All it does is
* define some common methods that both ServerThread and FileThread will use.
*/

import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;


public abstract class ServerThread extends Thread {

  // shared AES session key to be established upon connection
  protected Key sessionKey;
  protected boolean sessionKeyEstablished = false;

  // shared AES key for signing messages
  protected Key signingKey = null;

  // private key of server which this thread is running on
  protected PrivateKey privateKey;
  // public key of the server
  protected PublicKey publicKey;

  // for reading and writing to the socket
  protected ObjectInputStream input;
  protected ObjectOutputStream output;

  private byte[] iv = new byte[16];

  // sequence number to prevent message reordering
  private int sequenceNumber = -1;

  // constants for encryption algorithms
  protected final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  protected final String SHA1_PRNG = "SHA1PRNG";
  protected final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
  protected final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";

  /**
   * This method attempts to establish a public key between the client and server.
   * It is intended to be used by file servers when the client connects to them
   * for the first time.
   * @return true if the public key was successfully established
   */
  public boolean establishPublicKey() {
    try {
      // send public key to client
      Envelope message = new Envelope("KEY");
      message.addObject(publicKey);
      output.writeObject(message);

      // read response from client
      Envelope response = (Envelope) input.readObject();
      if (response.getMessage().equals(ResponseConstants.SUCCESS_KEY)) {
        return true;
      }
    } catch (Exception e) {
      System.out.println("Error in establishPublicKey:" + e.getMessage());
      return false;
    }

    return false;
  }

  /**
  * This method attempts to establish a shares secret session key with the client
  * by implementing the server side of the mechanism described in Protocol 1 of
  * the project writeup.
  */
  public boolean establishSessionKey() {
    // receive and decrypt first message from client
    Envelope message = readAndDecryptMessage();
    Envelope response = new Envelope(ResponseConstants.FAIL_CONNECT);

    boolean goodConnect = false;
    try {
      // check for proper structure of message
      if (message.getMessage().equals("CONNECT")) {
        // get challenge and AES key from decrypted message
        Integer challenge = (Integer) message.getObjContents().get(0);
        sessionKey = (Key) message.getObjContents().get(1);
        signingKey = (Key) message.getObjContents().get(2);

        // construct response message with incremented challenge
        response = new Envelope(ResponseConstants.SUCCESS_CONNECT);
        Integer challengeResponse = new Integer(challenge.intValue() + 1);
        response.addObject(challengeResponse);

        // add initial sequence number to the response
        SecureRandom random = SecureRandom.getInstance(SHA1_PRNG);
        sequenceNumber = new Integer(random.nextInt() & Integer.MAX_VALUE);

        sessionKeyEstablished = true;
        encryptAndWriteResponse(response);

        return true;
      }
    } catch (Exception e) {
      System.err.println("Error occurred while attempting to establish the session key.");
    }

    return false;
  }

  /**
  * This method reads an encrypted Envelope from the client and returns
  * the decryption.
  */
  public Envelope readAndDecryptMessage() {
    try {
      setIV();
      SealedObject encryptedResponse;
      if (signingKey != null) {
        Envelope signedResponse = (Envelope) input.readObject();
        if (!verifySignature(signedResponse)) {
          throw new Exception("Invalid signature on the received message.");
        }
        encryptedResponse = (SealedObject) signedResponse.getObjContents().get(0);
      } else {
        encryptedResponse = (SealedObject) input.readObject();
      }

      Envelope response = (Envelope) decryptObject(encryptedResponse);

      int responseSize = response.getObjContents().size();
      int responseSequenceNumber = (Integer) response.getObjContents().get(responseSize - 1);
      if (responseSequenceNumber != sequenceNumber + 1) {
        throw new Exception("Invalid sequence number: " + responseSequenceNumber + ". Expecting: " + (sequenceNumber + 1));
      }

      sequenceNumber = responseSequenceNumber;
      return response;
    } catch (Exception e) {
      System.err.println("Error reading and decrypting response from client: " + e.getMessage());
      return null;
    }
  }

  /**
  * This method encrypts and sends an Envelope to the client.
  */
  public void encryptAndWriteResponse(Envelope message) {
    // increment sequence number and add it to the message
    message.addObject(new Integer(++sequenceNumber));

    // encrypt, sign, and send the object
    try {
      SealedObject encryptedMessage = encryptObject(message);
      Envelope signedMessage = signObject(encryptedMessage);
      output.writeObject(signedMessage);
    } catch (Exception e) {
      System.err.println("Error encrypting and writing message to client.");
    }
  }

  /**
  * This method takes an Object and encrypts it using either the private
  * RSA key or the shared secret AES key of the group server.
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
        // generate and initialize an AES cipher
        cipher = Cipher.getInstance(AES_CBC_PKCS5);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
      } else {
        // generate and initialize an RSA cipher
        cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      }

      return new SealedObject(obj, cipher);
    } catch (Exception e) {
      System.err.println("Error using AES or RSA algorithm for encryption.");
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
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
      }

      return sealedObj.getObject(cipher);
    } catch (Exception e) {
      System.err.println("Error using AES or RSA algorithm for decryption.");
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
   *  This method initializes the IV required for AES encryption and decryption.
   *  The IV's value will be determined by the client initiating communication
   *  with the server.
   */
  private void setIV() {
    try {
      for (int i = 0; i < 16; i++) {
        iv[i] = (byte)input.readObject();
      }
    } catch (Exception e) {
      System.err.println("Server: Error reading in IV");
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
