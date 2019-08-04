package com.futurepress.staticserver;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import fi.iki.elonen.SimpleWebServer;
import android.util.Log;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class WebServer extends SimpleWebServer
{
    public static final String TAG = "WebServer";

    public WebServer(String localAddr, int port, File wwwroot, String key, String salt, String iv, int keySize,
    int iterationCount) throws IOException {
        super(localAddr, port, wwwroot, true, "*");
        keyString = key;
        this.salt = salt;
        this.siv = iv;
        this.skey0size = keySize;
        this.siteration0count = iterationCount;
        mimeTypes().put("xhtml", "application/xhtml+xml");
        mimeTypes().put("opf", "application/oebps-package+xml");
        mimeTypes().put("ncx", "application/xml");
        mimeTypes().put("epub", "application/epub+zip");
        mimeTypes().put("otf", "application/x-font-otf");
        mimeTypes().put("ttf", "application/x-font-ttf");
        mimeTypes().put("js", "application/javascript");
        mimeTypes().put("svg", "image/svg+xml");
    }

    @Override
    public Response serve(IHTTPSession session) {
        String msg = "<html><body><h1>Hello server</h1>\n";
        Map<String, String> parms = session.getParms();
        String uri = session.getUri();
        Log.i(TAG,uri);
        if (uri.contains("file.key")) {
            isEncrypted = true;
        } else {
            isEncrypted = false;
        }
        return super.serve(session);
    }

    @Override
    protected boolean useGzipWhenAccepted(Response r) {

        if (isEncrypted) {
            InputStream inputStream = r.getData();
            byte[] encryptedBytes = inputStreamToBytes(inputStream);
            byte[] decryptedBytes = decryptFromBytes(encryptedBytes, keyString, salt, siv, siteration0count, skey0size);
            InputStream is = new ByteArrayInputStream(decryptedBytes); // convert a byte array into an InputStream
            String contentLength = "Content-Length";
            r.addHeader(contentLength, String.valueOf(decryptedBytes.length));
            r.setData(is);
            return super.useGzipWhenAccepted(r) && r.getStatus() != Response.Status.NOT_MODIFIED;
        }
        return super.useGzipWhenAccepted(r) && r.getStatus() != Response.Status.NOT_MODIFIED;
    }

    private static byte[] inputStreamToBytes(InputStream is) {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            //Log.i(TAG,"UTF-8");
            String st;
            StringBuilder sb = new StringBuilder();
            while ((st = br.readLine()) != null) {
                sb.append(st);
            }
            byte[] decodedBytes = android.util.Base64.decode(sb.toString(), android.util.Base64.NO_WRAP);//NO_WRAP
            return decodedBytes;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decryptFromBytes(byte[] encryptedBytes, String passphrase, String salt, String iv, int iterationCount,
            int keySize) {
        try {
            SecretKey key = generateKey(salt, passphrase, iterationCount, keySize);
            byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, encryptedBytes);
            //String temp = new String(decrypted, "UTF-8");
            //Log.i(TAG,passphrase);
            //Log.i(TAG,temp);
            return decrypted;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(encryptMode, key, new IvParameterSpec(hexStringToByteArray(iv)));
            return cipher.doFinal(bytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SecretKey generateKey(String salt, String passphrase, int iterationCount, int keySize) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), hexStringToByteArray(salt), iterationCount, keySize);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


    private static final String IV = "";
    private static final String SALT = "";
    private static final int KEY_SIZE = 128;
    private static final int ITERATION_COUNT = 100;
    private string salt = "";
    private string siv = "";
    private int skey0size = 0;
    private int siteration0count = 0;
    private static final String PASSPHRASE = "the quick brown fox jumps over the lazy dog";
    private boolean isEncrypted = false;
    private String keyString = "";
    private static SecretKeySpec secretKey;
    private static byte[] key;
}
