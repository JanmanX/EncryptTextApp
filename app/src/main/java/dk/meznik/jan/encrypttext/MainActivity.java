package dk.meznik.jan.encrypttext;

import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //setContentView(R.layout.activity_main);


        Intent intent = new Intent(this, EncryptActivity.class);
        startActivity(intent);
        finish();
    }
}
