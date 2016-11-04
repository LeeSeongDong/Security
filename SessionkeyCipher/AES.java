package main;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES 
{
	public byte[] encrypt(String input, String key)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("AES");
			SecretKeySpec SKS = new SecretKeySpec(key.getBytes(), "AES");
			cipher.init(Cipher.ENCRYPT_MODE, SKS);

			byte[] encryptBytes = cipher.doFinal(input.getBytes("UTF-8"));
			return encryptBytes;
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return null;
		}		
	}

	public String decrypt(byte[] input, String key)
	{
		try
		{
			Cipher cipher = Cipher.getInstance("AES");
			SecretKeySpec SKS = new SecretKeySpec(key.getBytes(), "AES");
			cipher.init(Cipher.DECRYPT_MODE, SKS);
			
			byte[] decryptBytes = cipher.doFinal(input);
			return new String(decryptBytes);
		}
		catch(Exception e)
		{
			e.printStackTrace();
			return null;
		}	
	}
	
	public static void main(String[] args)
	{
		AES aes = new AES();
		String key = "awdasdwfwadwasdw";
		String input = "aaaaaaaaaaa";
		
		System.out.println(aes.decrypt(aes.encrypt(input, key), key));
	}
}
