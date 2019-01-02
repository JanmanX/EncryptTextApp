package dk.meznik.jan.encrypttext;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import dk.meznik.jan.encrypttext.util.Encryption;

public class EncryptActivity extends AppCompatActivity {
    EditText editTextPassword;
    EditText editText1;
    EditText editText2;
    Button buttonEncrypt;
    Button buttonDecrypt;
    Button buttonReplace;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt);

        editTextPassword = findViewById(R.id.editTextPassword);
        editText1 = findViewById(R.id.editText1);
        editText2 = findViewById(R.id.editText2);
        buttonEncrypt = findViewById(R.id.buttonEncrypt);
        buttonDecrypt = findViewById(R.id.buttonDecrypt);
        buttonReplace = findViewById(R.id.buttonReplace);
        buttonReplace.setEnabled(false);


        // Set the editText with text to encrypt, depending on the intent type
        CharSequence text = "";

        if (getIntent().getAction() == null) {
            // App started from launcher
        } else if (getIntent().getAction().equals(Intent.ACTION_SEND)) {
            text = getIntent().getCharSequenceExtra(Intent.EXTRA_TEXT);
        } else if (getIntent().getAction().equals(Intent.ACTION_PROCESS_TEXT)) {
            text = getIntent().getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT);
            buttonReplace.setEnabled(true);

        }
        editText1.setText(text);

    }

    public void exitWithResult(String data) {
        Intent result = new Intent();
        result.putExtra(Intent.EXTRA_PROCESS_TEXT, data);
        setResult(RESULT_OK, result);
        finish();
    }

    public void buttonEncryptClick(View v) {
        String password = editTextPassword.getText().toString();
        String str = editText1.getText().toString();
        String cipher = "";
        try {
            cipher = Encryption.encrypt(password, str);
        } catch (Exception ex) {
            Toast.makeText(this, "Could not encrypt text: " + ex.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
        }
        editText2.setText(cipher);
    }

    public void buttonDecryptClick(View v) {
        String password = editTextPassword.getText().toString();
        String str = editText1.getText().toString();
        String plain = "";
        try {

            plain = Encryption.decrypt(password, str);

        } catch (Exception ex) {
            Toast.makeText(this, "Unable to decipher text.", Toast.LENGTH_SHORT).show();
        }

        editText2.setText(plain);
    }

    public void buttonReplaceClick(View v) {
        exitWithResult(editText2.getText().toString());
    }

    public void editText2Click(View v) {
        ClipboardManager clipboardManager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        String str = editText2.getText().toString();
        ClipData clipData = ClipData.newPlainText("Text", str);
        clipboardManager.setPrimaryClip(clipData);
        Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show();
    }

    public void imageButtonHelpClick(View v) {
        Toast.makeText(this, "TEST", Toast.LENGTH_SHORT).show();
    }
}
