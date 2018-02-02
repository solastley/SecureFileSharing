# Secure File Sharing System

This repository contains code from a semester-long project done in my Applied Cryptography course at the University of Pittsburgh. In summary, the project consisted of a "secure" file sharing system which consists of a file server, a group server, and a client application for accessing these servers, all of which are implemented in Java.

The basic idea is that clients will be able to access the respective servers to make groups and share files with other members of those groups in a secure manner, i.e. the confidentiality, integrity, and availability of files are maintained. These terms don't mean much without more context, which can be found in the `reports/` folder.

At a high level, the system uses a combination of cryptographic techniques including RSA, AES, HMAC, and TCP-like sequence numbers to protect against a multitude of threats including active man-in-the-middle attacks, compromised user password files, etc. For more details, you can read through the documents located in `reports/`.
