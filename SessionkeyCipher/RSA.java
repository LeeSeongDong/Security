package main;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA 
{
	private KeyFactory keyFactory;
	private KeyPair keyPair;

	public void init()
	{
		try 
		{
			keyFactory = KeyFactory.getInstance("RSA");

			// 공개키 및 개인키 생성
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);

			keyPair = keyPairGenerator.genKeyPair();
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		}
	}

	public PrivateKey getPrivateKey()
	{
		return keyPair.getPrivate();
	}

	public PublicKey getPublicKey()
	{
		return keyPair.getPublic();
	}

	public PublicKey restorePublicKey(byte[] pubBytes)
	{
		try 
		{
			X509EncodedKeySpec pubRestoreSpec = new X509EncodedKeySpec(pubBytes);
			PublicKey pubRestore = keyFactory.generatePublic(pubRestoreSpec);
			
			return pubRestore;
		} 
		catch (InvalidKeySpecException e) 
		{
			e.printStackTrace();
			return null;
		}
	}


	public byte[] encrypt(String input, Key publicKey)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptBytes = cipher.doFinal(input.getBytes());
			
			return encryptBytes;
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public String decrypt(byte[] input, Key privateKey)
	{
		try 
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decriptBytes = cipher.doFinal(input);
			
			return new String(decriptBytes);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		} 
		catch (NoSuchPaddingException e) 
		{
			e.printStackTrace();
		} catch (InvalidKeyException e) 
		{
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) 
		{
			e.printStackTrace();
		} catch (BadPaddingException e) 
		{
			e.printStackTrace();
		}
		
		return null;
	}
}
