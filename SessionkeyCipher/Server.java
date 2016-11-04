package main;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Server
{
	public static void main(String[] args) 
	{
		try 
		{
			AES aes = new AES();
			RSA rsa = new RSA();
			rsa.init();
			
			ServerSocket server = new ServerSocket(888);
			System.out.println("Server is Run!");
			Socket client = server.accept();

			DataOutputStream out = new DataOutputStream(client.getOutputStream());
			DataInputStream in = new DataInputStream(client.getInputStream());
			
			PrivateKey privateKey = rsa.getPrivateKey();
			PublicKey publicKey = rsa.getPublicKey();
			byte pubByte[] = publicKey.getEncoded();
			
			// 공개키전송
			System.out.println("Send Public Key");
			out.writeInt(pubByte.length);
			out.write(pubByte);
			
			// 암호화된 데이터
			byte readData[] = new byte[in.readInt()];
			in.readFully(readData);
			
			
			// 암호화된 AES 키
			byte readKey[] = new byte[in.readInt()];
			in.readFully(readKey);
			
			
			String aesKey = rsa.decrypt(readKey, privateKey);
			String decData = aes.decrypt(readData, aesKey);
			
			System.out.println("DEcrypted AES Key : " + aesKey);
			System.out.println("Decrypted Data : " + decData);
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
	}
}
