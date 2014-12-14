package com.example.simplepasswordstore;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.provider.Settings;
import android.widget.Toast;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;

public class PasswordStore {
	private ArrayList<byte[]> storedPasswords;
	private Cipher aescipher;
	private MainActivity mainactivity;
	private SecretKeyFactory keyFactory;
	private ArrayList<String> passwordNames;
	private byte[] salt = {
		    (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
		    (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
		};
	
	public PasswordStore(MainActivity activity)
	{
		storedPasswords = new ArrayList<byte[]>();
		passwordNames = new ArrayList<String>();
		mainactivity = activity;
		
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			failedCipherInit();
		} catch (NoSuchPaddingException e) {
			failedCipherInit();
		}
	}
	
	public ArrayList<String> getList()
	{
		return (ArrayList<String>) passwordNames.clone();
	}

	private void failedCipherInit() {
		AlertDialog.Builder builder1 = new AlertDialog.Builder(mainactivity);
		builder1.setMessage("Error initializing cipher.");
		builder1.setCancelable(true);
		builder1.setNegativeButton("Exit",
		        new DialogInterface.OnClickListener() {
		    public void onClick(DialogInterface dialog, int id) {
		        dialog.cancel();
		        mainactivity.exitApp();
		    }
		});
		AlertDialog alert11 = builder1.create();
		alert11.show();
	}
	
	public boolean addPassword(String password, String validation, String name)
	{
		char[] validationPassword = validation.toCharArray();
		try{
			SecretKey secKey = makeAESKey(validationPassword);
		
			byte[] bytedPassword = password.getBytes();
			aescipher.init(Cipher.ENCRYPT_MODE, secKey);
			byte[] ciphertext = aescipher.doFinal(bytedPassword);
			storedPasswords.add(ciphertext);
			passwordNames.add(name);
		}
		catch(IllegalBlockSizeException e) {
			return false;
		}
		catch(BadPaddingException e) {
			return false;
		}
		catch(InvalidKeyException e) {
			return false;
		}
		catch(InvalidKeySpecException e) {
			return false;
		}
		
		return true;
	}
	
	public String retrievePassword(int index, String validation) throws InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		char[] validationPassword = validation.toCharArray();
		
		SecretKey secKey = makeAESKey(validationPassword);
		
        aescipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePassword = aescipher.doFinal(storedPasswords.get(index));
        return bytePassword.toString();
	}

	private SecretKey makeAESKey(char[] validationPassword)
			throws InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec(validationPassword, salt, 65536, 256);
		SecretKey tmp = keyFactory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		
		return secret;
	}
	
	public void removePassword(int index)
	{
		storedPasswords.remove(index);
		passwordNames.remove(index);
	}
	
}
