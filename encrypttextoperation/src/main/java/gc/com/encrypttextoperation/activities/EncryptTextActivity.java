package gc.com.encrypttextoperation.activities;

import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import gc.com.encrypttextoperation.R;
import gc.com.keystoremanager.KeystoreManager;
import gc.com.keystoremanager.KeystoreManagerException;

/**
 * Created by xcelder1 on 18/7/16.
 */
public class EncryptTextActivity extends FragmentActivity {

    @BindView(R.id.et_text_to_encrypt)
    EditText txtToEncrypt;

    @BindView(R.id.tv_encrypted_text)
    TextView txtEncrypted;

    @BindView(R.id.tv_decrypted_text)
    TextView txtDecrypted;

    @BindView(R.id.btn_decrypt)
    TextView btnDecrypt;


    KeystoreManager keystoreManager;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt_text);
        ButterKnife.bind(this);
        try {
            keystoreManager = new KeystoreManager(this);
        } catch (KeystoreManagerException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    @OnClick(R.id.btn_encrypt)
    public void onClickEncrypt() {
        if (txtToEncrypt.getText().toString().isEmpty()) {
            Toast.makeText(this, "You must to introduce text first", Toast.LENGTH_SHORT).show();
        }else{
            try {
                String result = keystoreManager.encryptText(txtToEncrypt.getText().toString());
                txtEncrypted.setText(result);
                btnDecrypt.setEnabled(true);
            } catch (KeystoreManagerException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    @OnClick(R.id.btn_decrypt)
    public void onClickDecrypt(){
        if(txtEncrypted.getText().toString().isEmpty()){
            Toast.makeText(this, "You must to encrypt text first", Toast.LENGTH_SHORT).show();
        }else{
            try {
                String decrypted = keystoreManager.decryptText(txtEncrypted.getText().toString());
                txtDecrypted.setText(decrypted);
            } catch (KeystoreManagerException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

}
