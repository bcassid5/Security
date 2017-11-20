/*
 * SE4472 Assignment 2 - Question 1
 * Ben Cassidy
 * 
 * Disclaimer: assistance for the program below was achieved through stack exchange and open source projects.  
 * */

package sign;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class sign {
	private static String n_string;
	private static String d_string;
	private static String e_string;

	public static void main(String[] args) throws  InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NoSuchProviderException   {
		
		
		//added external security provider for Java 
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		//taking values of n,d,e from assignment2-values txt file
		n_string = "96593720236010659771827402676643429789938619440952555364622074956435340200061656508060615789030840134203664978505512524142393395270050853990539724973005030936743555266850207882401594704734189906511529782800955972664184033920361943962669563041630205806431828596746559268709959974499729037311769911690888754219";
		d_string = "17487594650354249938091950085575694561203926326607901939381432158293869287177190815388852195505606271149525992492300625584776502355602993463200235543352678006383997467860705323250971456335829396517506516991764156256889079821612990896638819945492250519738119781570884479786708912307843283470457443387159862073";
		e_string = "65537";
		//file name of my code file for creating RSA signature
	    String file_name = "sign.java";

		//converting values of n, d, e into biginteger
		BigInteger n_value = new BigInteger(n_string);
		BigInteger d_value = new BigInteger(d_string);
		BigInteger e_value = new BigInteger(e_string);
		
		//creating keyspace and passing values to get the private signing key (n, d)
		KeySpec KEYS_private = new RSAPrivateKeySpec(n_value, d_value);
		PrivateKey private_key = KeyFactory.getInstance("RSA").generatePrivate(KEYS_private);
		//System.out.println("Private Key: " + private_key);
		
		//creating keyspace and passing values to get the public key
		KeySpec KEYS_public = new RSAPublicKeySpec(n_value, e_value);
		PublicKey public_key = KeyFactory.getInstance("RSA").generatePublic(KEYS_public);
		//System.out.println("Public Key: " + public_key);
	 			    
        //signing signature for the sign.java file name
		Signature signature_instance = Signature.getInstance("SHA256withRSA","BC");		//using SHA256 with RSA as per assignment, and external security provider
		signature_instance.initSign(private_key);///
		signature_instance.update((file_name).getBytes());
		byte[] signature = signature_instance.sign();

        //creating the hash for sign.java for signing the signature 
		MessageDigest digest = MessageDigest.getInstance("SHA256", "BC");			//using SHA256 again with external security provider
		byte[] hash_array = digest.digest((file_name).getBytes());
		
		//change the signature to the form where we can get padding, ASN header, signature
		Cipher cipher = Cipher.getInstance("RSA","BC");
		cipher.init(Cipher.DECRYPT_MODE, public_key);
		byte[] cipher_Text = cipher.doFinal(signature);

		//covert the hash value of the filename to hexadecimal 
		String hexvalueof_hash = DatatypeConverter.printHexBinary(hash_array);
		String hexvalueof_signature = DatatypeConverter.printHexBinary(signature);
		String hexvalueof_cipher = DatatypeConverter.printHexBinary(cipher_Text);
	
		//print values 
		System.out.println("File name: " + file_name);
		System.out.println("Hash of file name: "+ hexvalueof_hash);
		System.out.println("RSA Signature of the given file name: " + hexvalueof_signature);
		System.out.println("sig^e mod n: 00" + hexvalueof_cipher);
		/*
		 * sig^e mod n was outputted and checked. Upon breaking up the modified signature we get the below:
		 * sig^e mod n = 0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D06096086480165030402010500042041820D8EFD6020307DB4953D9CE8312280979BDA27728E8CE330053EC03B2BAF
		 * 
		 * PKCS 1.5 Padding: 0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00
		 * ASN.1 encoding - SHA256: 3031300D060960864801650304020105000420
		 * File hash: 41820D8EFD6020307DB4953D9CE8312280979BDA27728E8CE330053EC03B2BAF
		 * */
	}
}
