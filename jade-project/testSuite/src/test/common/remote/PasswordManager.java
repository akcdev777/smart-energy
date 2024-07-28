package test.common.remote;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {
	public static final String HELP_OPTION = "help";
	public static final String OPERATION_OPTION = "o";
	public static final String PASSWORD_OPTION = "p";
	private static final String SECRET_KEY = "my_super_secret_key_ho_ho_ho";
	private static final String SALT = "ssshhhhhhhhhhh!!!!";

	public static String encrypt(String strToEncrypt) {
		try {
			// Create default byte array
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Create SecretKeyFactory object
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

			// Create KeySpec object and assign with
			// constructor
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
			// Return encrypted string
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
		}
		catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
			e.printStackTrace();
		}
		return null;
	}

	public static String decrypt(String strToDecrypt)
	{
		try {
			// Default byte array
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			// Create IvParameterSpec object and assign with
			// constructor
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// Create SecretKeyFactory Object
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

			// Create KeySpec object and assign with
			// constructor
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			// Return decrypted string
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		}
		catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
			e.printStackTrace();
		}
		return null;
	}
	
	public static Properties parseCommandLine(String[] args) throws IllegalArgumentException {
		Properties props = new Properties();
		if (args != null) {
			int i = 0;
			while (i < args.length) {
				if (args[i].startsWith("-")) {
					// Parse next option
					String name = args[i].substring(1);
					if (name.equals(HELP_OPTION)) {
						props.setProperty(name, "true");
					}
					else {
						if (++i < args.length) {
							props.setProperty(name, args[i]);
						}
						else {
							throw new IllegalArgumentException("No value specified for property \""+name+"\"");
						}
					}
					++i;
				}
				else {
					throw new IllegalArgumentException("Invalid argument "+args[i]+": options must have the form \"-key value\"");
				}
			}
		}

		return props;
	}
	
	private static void printUsage() {
		System.out.println();
		System.out.println("USAGE: PasswordManager options");
		System.out.println();
		System.out.println("Options:");
		System.out.println("-o: Operation (encrypt|decrypt)");
		System.out.println("-p: Password");
		System.out.println("-"+HELP_OPTION+": Print this help and terminate");
	}
	
	public static void main(String[] args) {
		try {
			// Parse command line
			Properties props = parseCommandLine(args);
			if (props.isEmpty() || props.containsKey(HELP_OPTION)) {
				printUsage();
				return;
			}
			
			// Extract properties
			String operation = props.getProperty(OPERATION_OPTION);
			String password = props.getProperty(PASSWORD_OPTION);

			// Check properties
			if (operation == null || operation.trim().isEmpty() ||
				password == null || password.trim().isEmpty()) {
				
				System.out.println("WARNING: mandatory options not present!");
				printUsage();
				return;
			}
			
			if (operation.equalsIgnoreCase("encrypt")) {
				String encriptedPassword = encrypt(password);
				
				// Print report
				System.out.println();
				System.out.println("PasswordManager encrypt");
				System.out.println();
				System.out.println(password + " -> " + encriptedPassword);
				System.out.println();
			}
			else if (operation.equalsIgnoreCase("decrypt")) {
				String decriptedPassword = decrypt(password);

				// Print report
				System.out.println();
				System.out.println("PasswordManager decrypt");
				System.out.println();
				System.out.println(password + " -> " + decriptedPassword);
				System.out.println();
			}
			else {
				System.out.println("WARNING: wrong operation (encrypt|decrypt)");
				printUsage();
				return;
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}			
	}
}
