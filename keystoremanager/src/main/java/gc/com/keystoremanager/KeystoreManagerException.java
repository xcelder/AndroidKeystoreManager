package gc.com.keystoremanager;

/**
 * Created by xcelder1 on 11/7/16.
 */
public class KeystoreManagerException extends Exception {

    static final String EXCEPTION_EMPTY_TEXT = "Error attempting to encrypt an empty String";

    public KeystoreManagerException (String message){
        super(message);
    }

}
