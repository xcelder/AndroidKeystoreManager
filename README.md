# AndroidKeystoreManager
Android source for an easy implementation of utils from Keystore: encryption and decryption. Minimum API 18 (compatibility with Android M or higher)

NEW! ButterCookie included in the Demo, an example that will help you learn how to inject your views in a library.
https://github.com/JackCho/ButterCookie/blob/master/library/src/main/java/me/ele/buttercookie/LibraryActivity.java

## How to use

```java
  KeystoreManager keystoreManager = new KeystoreManager(this);
  // Encrypt Text 
  String encryptedText = keystoreManager.encryptText("Text");
  // Decrypt Text 
  String decryptedText = keystoreManager.decryptText("wewr23e2wdsawe2wdsaqwe2wdsaqwe");
```
