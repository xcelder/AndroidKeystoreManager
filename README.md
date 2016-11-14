# AndroidKeystoreManager
Android source for an easy implementation of utils from Keystore: encryption and decryption. Minimum API 18 (compatibility with Android M or higher)

NEW! ButterCookie included in the Demo, an example that will help you learn how to inject your views in a library.
https://github.com/JackCho/ButterCookie

## How to use

```java
	KeystoreManager.init(context);

  // Encrypt Text 
  String encryptedText = KeystoreManager.getInstance().encryptText("Text");
  // Decrypt Text 
  String decryptedText = KeystoreManager.getInstance().decryptText("wewr23e2wdsawe2wdsaqwe2wdsaqwe");
```
## Use for save preferences

```java
  KeystoreManager.init(context);
  
  // Save preference 
  KeystoreManager.getInstance().setPreference("key","value");
  
  // Get preference
  String preference = KeystoreManager.getInstance().getPreference("key");
  
  // Remove preference 
  KeystoreManager.getInstance().removePreference("key");

```
