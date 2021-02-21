package mx.xx.securecommunicationsdemo;

import android.os.AsyncTask;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

public class MainActivity extends AppCompatActivity {

    public static String TAG = "SCOMM";
    private Button button;
    private EditText plainInput;
    private EditText responseEditText;
    public String keyStr = "00112233445566778899aabbccddeeff";
    public String ivStr = "1111111111111111";
    public byte[] key = keyStr.getBytes();
    public byte[] iv = ivStr.getBytes();

    private class ReadTask extends AsyncTask<String, Integer, String> {
        @Override
        protected String doInBackground(String... params) {
            return getResponseFromUrl(params[0], params[1]);
        }

        private String getResponseFromUrl(String urlString, String xmlString) {
            try {
                URL url = new URL(urlString);
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/xml");
                conn.setDoInput(true);
                conn.setDoOutput(true);

                OutputStream os = conn.getOutputStream();
                BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(os, "UTF-8"));
                writer.write(xmlString);
                writer.flush();
                writer.close();

                InputStream in = conn.getInputStream();
                BufferedReader r = new BufferedReader(new InputStreamReader(in));
                StringBuilder total = new StringBuilder();

                String line;

                while ((line = r.readLine()) != null) {
                    total.append(line);
                }
                Log.d(TAG, "Received: " + total.toString());

                final String backText = total.toString();

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        int endIndex = backText.indexOf("</response>");
                        String substr = backText.substring(10,endIndex);
                        byte[] encResp = Base64.decode(substr,Base64.DEFAULT);
                        try {
                            String decResp = decryptAES(key,encResp,iv);
                            responseEditText.setText(new String(Base64.decode(decResp,Base64.DEFAULT),"UTF-8"));
                        } catch (Exception e) {
                            responseEditText.setText("Error decrypting " + substr);
                            e.printStackTrace();
                        }
                    }
                });

                return total.toString();
            } catch (MalformedURLException e) {
                e.printStackTrace();
                return "M";
            } catch (IOException e) {
                e.printStackTrace();
                return e.getMessage();
            }
        }
    }

    public byte[] encryptRSA(byte[] original) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {

        InputStream instream = getResources().openRawResource(R.raw.server_public_pkcs8);
        byte[] encodedKey = new byte[instream.available()];
        instream.read(encodedKey);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pkPublic = kf.generatePublic(publicKeySpec);

        Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        try {
            pkCipher.init(Cipher.ENCRYPT_MODE, pkPublic);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        try {
            return pkCipher.doFinal(original);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
    private static byte[] encryptAES(byte[] key, byte[] clear, byte[] iv) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private static String decryptAES(byte[] key, byte[] encrypted, byte[] iv) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return Base64.encodeToString(decrypted, Base64.DEFAULT);
    }

    private byte[] signRSA(byte[] msg) {
        try {
            //byte[] sign = encryptRSA(hash);
            InputStream instream = getResources().openRawResource(R.raw.client_private_pkcs8_2);
            byte[] encodedKey = new byte[instream.available()];
            instream.read(encodedKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pkPrivate = kf.generatePrivate(keySpec);

            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initSign(pkPrivate);
            instance.update(msg);
            byte[] signature = instance.sign();
            return signature;

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void startComm(String msg) {
        byte[] plain = msg.getBytes();
        String endpointURL = "https://2006.labs.defdev.eu:9998/request";
        try {

            byte[] aesresult = encryptAES(key, plain, iv);
            String aesresultString = Base64.encodeToString(aesresult, Base64.DEFAULT);
            Log.d(TAG, "AES encryption result: " + aesresultString);

            String toEncrypt = keyStr + "|" + ivStr;
            byte[] rsaresult = encryptRSA(toEncrypt.getBytes());
            String rsaresultString = Base64.encodeToString(rsaresult, Base64.DEFAULT);
            Log.d(TAG, "RSA encryption result: " + rsaresultString);

            byte[] rsasignature = signRSA(aesresult);
            Log.d(TAG,"RSA signature: " + new String(rsasignature));
            String rsaSignatureString = Base64.encodeToString(rsasignature, Base64.DEFAULT);

            String paramXML = "<?xml version=\"1.0\" ?>" +
                    "<request>" +
                    "<enckey>" + rsaresultString + "</enckey>" +
                    "<message>" + aesresultString + "</message>" +
                    "<signature>" + rsaSignatureString + "</signature>" +
                    "</request>";

            AsyncTask<String, Integer, String> rt = new ReadTask();
            rt.execute(endpointURL, paramXML);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button = (Button) findViewById(R.id.sendButton);
        plainInput = (EditText) findViewById(R.id.messageText);
        responseEditText = (EditText) findViewById(R.id.responseText);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View arg0) {
                startComm(plainInput.getText().toString());
            }
        });
    }
}
