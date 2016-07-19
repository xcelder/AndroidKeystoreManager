package gc.com.androidkeystoremanager.activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.widget.Button;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import gc.com.androidkeystoremanager.R;
import gc.com.encrypttextoperation.activities.EncryptTextActivity;

/**
 * Created by xcelder1 on 16/7/16.
 */

public class MainActivity extends FragmentActivity {

    @BindView(R.id.btn_bytes)
    Button btnBytes;

    @BindView(R.id.btn_txt)
    Button btnTxt;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main_activity);
        ButterKnife.bind(this);
    }

    @OnClick(R.id.btn_txt)
    public void onTxtClicked(){
        Intent intent = new Intent(this, EncryptTextActivity.class);
        startActivity(intent);
    }
}
