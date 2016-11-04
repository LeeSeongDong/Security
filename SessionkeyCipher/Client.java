package main;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;

public class Client 
{
	public static void main(String[] args) 
	{
		AES aes = new AES();
		String aesKey = "aaaaaaaaaaaaaaaa";
		
		RSA rsa = new RSA();
		rsa.init();
		
		Scanner sc = new Scanner(System.in);
		try
		{
			Socket s = new Socket("localhost", 888);
			DataOutputStream out = new DataOutputStream(s.getOutputStream());
			DataInputStream in = new DataInputStream(s.getInputStream());
		
			byte pubK[] = new byte[in.readInt()];
			in.readFully(pubK);
			PublicKey publicKey = rsa.restorePublicKey(pubK);
			System.out.println(publicKey);
			
			System.out.print("Send : ");
			String inputData = sc.nextLine();
			byte encData[] = aes.encrypt(inputData, aesKey);
			
			// 암호화된 데이터 전송
			byte sendData[] = encData;
			out.writeInt(sendData.length);
			out.write(sendData);
			System.out.println("Encrypted Data : " + encData);
			
			// 키 암호화 해서 전송
			sendData = rsa.encrypt(aesKey, publicKey);
			out.writeInt(sendData.length);
			out.write(sendData);
			System.out.println("Encrypted AES Key : " + sendData);
			
			System.out.println("Data : " + aes.decrypt(encData, aesKey));
		}
		catch(Exception e)
		{
			e.printStackTrace();            
		}
	}
}


