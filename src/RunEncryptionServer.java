/* Driver program for FileSharing Encryption Server */

public class RunEncryptionServer {

	public static void main(String[] args) {
		if (args.length > 0) {
			try {
				EncryptionServer server = new EncryptionServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Set a valid port number or pass no arguments to use the default port (%d).\n", EncryptionServer.SERVER_PORT);
			}
		}
		else {
			System.out.printf("Group server port number is not specified. Starting with default port (%d).\n", EncryptionServer.SERVER_PORT);
			EncryptionServer server = new EncryptionServer();
			server.start();
		}
	}
}
