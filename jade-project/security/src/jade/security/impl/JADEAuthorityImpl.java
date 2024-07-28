/*****************************************************************
JADE - Java Agent DEvelopment Framework is a framework to develop
multi-agent systems in compliance with the FIPA specifications.
Copyright (C) 2002 TILAB S.p.A.

GNU Lesser General Public License

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation,
version 2.1 of the License.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA  02111-1307, USA.
 *****************************************************************/

package jade.security.impl;

import jade.core.Agent;
import jade.core.Profile;
import jade.core.security.SecurityHelper;
import jade.core.security.authentication.UserPassCredential;
import jade.domain.FIPAAgentManagement.SecurityObject;
import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.security.SecurityFactory;
import jade.security.util.SecurityData;
import jade.security.util.SecurityStore;
import jade.util.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the base class to perform cryptographic operations.
 * JADEAuthorityImpl has methods for signing and encrypting on behalf of
 * a principal.
 * @author Giosue Vitaglione - Telecom Italia LAB
 * @author Nicolas Lhuillier - Motorola
 * @author Jerome Picault - Motorola
 * @version $Date: 2007-04-24 16:20:28 +0200 (mar, 24 apr 2007) $ $Revision: 1001 $
 */
public class JADEAuthorityImpl implements jade.security.JADEAuthority {

	// Error message logger
	private Logger myLogger = Logger.getMyLogger(this.getClass().getName());

	// the JADEPrincipal for this Authority
	private JADEPrincipal myPrincipal = null;

	// The securitystore used
	private SecurityStore securityStore = null;

	// The keyPair used
	private KeyPair keyPair;

	// Default parameters for key generation
	private String keyAlgo = "RSA"; 
	private int    keySize = 512;     // for RSA: 512, 1024, 2048

	// Generic object to represent a container or an agent (see getProperty)
	private Object propHolder = null;

	// credentials needed for initiating this Authority
	private Credentials initCredentials = null;

	/**
	 * Uniformize property retrieval for all types of Principals
	 * (i.e. Agents and Containers)
	 */
	private String getProperty(String prop, String defVal) {
		String val = null;
		if (propHolder instanceof Agent ) {
			val = ((Agent)propHolder).getProperty(prop, defVal);
		} 
		else if (propHolder instanceof Profile) {
			val = ((Profile)propHolder).getParameter(prop, defVal);
		}
		return val;
	}


	private void setCryptoParameters(){
		keyAlgo= getProperty( SecurityHelper.ASYM_ALGO_KEY, SecurityHelper.ASYM_ALGO_DEFAULT );
		keySize = Integer.parseInt( getProperty( SecurityHelper.ASYM_KEYSIZE_KEY, SecurityHelper.ASYM_KEYSIZE_DEFAULT ) );
	}

	/**
	 * Default initialization method for an agent who does not have a key pair
	 */
	/*
  private void init(Agent myAgent) throws Exception {
    propHolder = myAgent; 
    // set default parameters for key pair
    keyAlgo = getProperty(SecurityHelper.KEY_ALGO,keyAlgo);
    keySize = Integer.parseInt(getProperty(SecurityHelper.KEY_SIZE,""+keySize));

    // TODO change user name and password
    init(myAgent.getLocalName(), 
         new UserPassCredential(myAgent.getLocalName(),myAgent.getName().getBytes()));
  }

  public void init(Agent myAgent, Credentials init) throws Exception  {
    init(myAgent); // TOFIX: credentials should be used here
  }
	 */

	public void init(String authName, Profile prof, Credentials initCreds) {
		propHolder = prof; 
		init(authName, initCreds);
	}

	/*
    public void init(String authorityName, Agent myAgent) {
    // myAgent is only used to get the Profile
    init(authorityName, myAgent, null);
    }

    public void init(String authorityName, Agent myAgent, Credentials initCredentials) {
    // myAgent is only used to get the Profile
    this.authorityName = authorityName;
    // credentials (if any, eg.username/password) neded to init the Authority
    this.initCredentials = initCredentials;
    propertyContainer = myAgent;
    init ();
    }

    public void init(String authorityName, Profile myProfile) {
    init (authorityName, myProfile, null); 
    }

    public void init(String authorityName, Profile myProfile, Credentials initCredentials) {
    this.authorityName = authorityName;
    this.initCredentials = initCredentials;
    propertyContainer = myProfile;
    init ();
    }
	 */

	/**
	 * Initialize the Authority for a Principal
	 * This means...
	 *   - Load configuration parameters from the Profile,
	 *   - Load the keypair from the SecurityStore (or create one)
	 * If this is the default authority of an agent: authorityName is 
   the (local) agent name.
	 * If it is of a container: it is the container name.
	 * If it is of a platform, it is the ams complete name.
	 */
	private void init (String name, Credentials initCreds) {

		// Load some configurable parameters from the Profile
		setCryptoParameters();

		// this is the asymmetric Chipher for encryption and signature
		// aCipher = Cipher.getInstance(encryptionAlgo); // Use default provider

		if (initCreds instanceof UserPassCredential) {
			myLogger.log(Logger.FINEST,"JADEAuthorityImpl: in init(...)");
			UserPassCredential upc = (UserPassCredential) initCreds;
			securityStore = new SecurityStore(upc.getUsername());
			securityStore.open(upc.getUsername(), upc.getPassword());
		} 
		else {
			myLogger.log(Logger.SEVERE,"Credential not supported: "+initCreds.getClass());
			// TODO throw an exception
		}

		// load the key pair (if exists, otherwise create a new one into the store)
		//#PJAVA_EXCLUDE_BEGIN
		java.util.logging.Level LEV1 = java.util.logging.Level.CONFIG;
		//#PJAVA_EXCLUDE_END
		/*#PJAVA_INCLUDE_BEGIN
    int LEV1 = jade.util.Logger.CONFIG;
    #PJAVA_INCLUDE_END*/        
		if (securityStore.hasMyKeyPair()) {
			myLogger.log(LEV1,"Principal "+name+" already had a key pair, loading it.");
			keyPair = securityStore.getMyKeyPair();
		}
		else {
			myLogger.log(LEV1,"Principal "+name+" does not have a key pair, creating it.");
			// a file does not exist
			// ask the store to generate a key pair for itself
			keyPair = SecurityStore.generateNewKeyPair(keySize,keyAlgo);
			securityStore.setMyKeyPair(keyPair);
			securityStore.flush();
		}

		myLogger.log(Logger.FINEST, "Authority keyPair = " + keyPair);

		PublicKey k = keyPair.getPublic();
		SDSINameImpl sdsi = new SDSINameImpl(k.getEncoded(),k.getAlgorithm(),k.getFormat());
		myPrincipal = SecurityFactory.getSecurityFactory().newJADEPrincipal(name,sdsi);
		myLogger.log(Logger.FINEST,"Principal = "+myPrincipal);
		securityStore.close();

	} // end init


	/**
	 *     Encrypt the given text by using your own private key.
	 *
	 *     (Typically, this is used for encrypting a hash for creating a signature)
	 */
	/*
  public byte[] asymEncrypt(byte[] text) {
    byte[] retVal=null;
    try {

      // initialize the cipher
      aCipher.init( Cipher.ENCRYPT_MODE, keyPair.getPrivate() );
      boolean thereAreBytesLeftToEncrypt = true;

      int blockSize = aCipher.getBlockSize();
      byte[] bytesLeftToEncrypt = text;
      int position = 0;
      ByteArrayOutputStream encryptedBytes = new ByteArrayOutputStream();
      while (thereAreBytesLeftToEncrypt) {
        int length;
        int numberOfBytesLeftToEncrypt =
          bytesLeftToEncrypt.length - position;
        if (blockSize <= numberOfBytesLeftToEncrypt)
        {
          length = blockSize;
        } else {
          length = numberOfBytesLeftToEncrypt;
        }	encryptedBytes.write(
                               aCipher.doFinal(bytesLeftToEncrypt, position, length));
        position += blockSize;
        if (position >= bytesLeftToEncrypt.length)
        {
          thereAreBytesLeftToEncrypt = false;
        }
      } // end while
      retVal = encryptedBytes.toByteArray();

    } catch (Exception e) { e.printStackTrace(); }
    return retVal;
  }
	 */


	/**
	 *     Decrypt the given text by using your own Public key.
	 *     (Typically, this is used for decrypting a hash for for verifying a signature)
	 *
	 */
	/*
  public byte[] asymDecrypt(byte[] text) {
    byte[] retVal=null;
    try {
      // initialize the cipher
      aCipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());

      int blockSize = aCipher.getBlockSize();
      byte[] bytesLeftToEncrypt = text;
      int position = 0;

      boolean thereAreBytesLeftToDecrypt = true;
      blockSize = aCipher.getBlockSize();
      byte[] bytesLeftToDecrypt = text;
      position = 0;
      ByteArrayOutputStream decryptedBytes = new ByteArrayOutputStream();
      while (thereAreBytesLeftToDecrypt) {
        int length;
        int numberOfBytesLeftToDecrypt =
          bytesLeftToDecrypt.length - position;
        if (blockSize <= numberOfBytesLeftToDecrypt) {
          length = blockSize;
        } else {
          length = numberOfBytesLeftToDecrypt;
        }
        decryptedBytes.write(
                             aCipher.doFinal(bytesLeftToDecrypt, position, length));
        position += blockSize;
        if (position >= bytesLeftToDecrypt.length)
        {
          thereAreBytesLeftToDecrypt = false;
        }
      } // end while
      retVal = decryptedBytes.toByteArray();

    } catch (Exception e) { e.printStackTrace(); }
    return retVal;
  }
	 */

	/**
	 * Creates a symmetric-key using 
	 */
	private SecretKey createSecretKey(int size, String algo) throws JADESecurityException{
		try{
			KeyGenerator kGen = KeyGenerator.getInstance(algo);
			kGen.init(size);
			return kGen.generateKey();
		} catch (NoSuchAlgorithmException e){
			throw new JADESecurityException("No such algorithm: "+algo);
		}
	}

	/**
	 * Calculate the signature of a certain 'text'
	 * by using the own private key
	 */
	public SecurityData sign(String algorithm, byte[] text) throws JADESecurityException {
		SecurityData sd  = new SecurityData();
		// TOSO: retrieve the private key based on the SDSIName info
		PrivateKey key = keyPair.getPrivate();
		try{
			Signature sig = Signature.getInstance(algorithm);
			sig.initSign(key);
			sig.update(text,0,text.length);
			sd.algorithm = algorithm;
			sd.data = sig.sign();
			sd.key = myPrincipal;
			return sd;
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (SignatureException se){
			throw new JADESecurityException(se.getMessage());
		}
	}

	/**
	 * Verify signature with a given public key
	 */
	public boolean verifySignature(SecurityData sd, byte[] text) throws JADESecurityException {
		try{
			Signature sig = Signature.getInstance(sd.algorithm);
			// Generate the public key object 
			PublicKey pubKey = publicKeyFromBytes(sd.key);
			sig.initVerify(pubKey);
			sig.update(text, 0, text.length);
			return sig.verify(sd.data);
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (SignatureException se){
			throw new JADESecurityException(se.getMessage());
		}
	}



	/**
	 * Encrypts a certain 'text'  
	 */
	public byte[] encrypt(SecurityObject so, byte[] text, JADEPrincipal recKey) throws JADESecurityException {
		SecurityData sd = (SecurityData)so.getEncoded();
		// creates a secret key
		SecretKey symKey = createSecretKey(sd.size,sd.algorithm);
		// encrypts the text with the symmetric key
		byte[] enc = symEncrypt(text,symKey);
		// encrypts the secret key with the receiver's public key
		byte[] wrapped = asymEncrypt(symKey.getEncoded(),recKey);
		// put the wrapped key in the SO
		sd.data = wrapped;
		sd.key = recKey;
		return enc;
	}

	/**
	 * Decrypt a certain encrypted text
	 */
	public byte[] decrypt(SecurityObject so, byte[] enc) throws JADESecurityException {
		SecurityData sd = (SecurityData)so.getEncoded();
		PrivateKey pk = keyPair.getPrivate();
		SecretKey sk = secretKeyFromBytes(asymDecrypt(pk,sd.data),sd.algorithm);
		return symDecrypt(enc,sk);
	}


	/** 
	 * Encrypts the given text with the given secret key
	 */
	private byte[] symEncrypt(byte[] text, SecretKey secret) throws JADESecurityException{
		try{
			// creation of the cipher
			Cipher cipher = Cipher.getInstance(secret.getAlgorithm());
			// initialisation of the cipher
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			myLogger.log(Logger.FINE, "Symmetric encryption: payload-length = "+text.length+", algorithm = "+cipher.getAlgorithm()+", block-size "+cipher.getBlockSize());
			return cipher.doFinal(text);
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (NoSuchPaddingException nspe){
			throw new JADESecurityException(nspe.getMessage());
		} catch (BadPaddingException bpe){
			throw new JADESecurityException(bpe.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (IllegalBlockSizeException ike){
			throw new JADESecurityException(ike.getMessage());
		}
	}

	/** 
	 * Decrypts the given text with the given secret key
	 */
	private byte[] symDecrypt(byte[] enctext, SecretKey secret) throws JADESecurityException{
		try{
			// creation of the cipher
			Cipher cipher = Cipher.getInstance(secret.getAlgorithm());
			// initialisation of the cipher
			cipher.init(Cipher.DECRYPT_MODE, secret);
			myLogger.log(Logger.FINE, "Symmetric decryption: payload-length = "+enctext.length+", algorithm = "+cipher.getAlgorithm()+", block-size "+cipher.getBlockSize());
			return cipher.doFinal(enctext);
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (NoSuchPaddingException nspe){
			throw new JADESecurityException(nspe.getMessage());
		} catch (BadPaddingException bpe){
			throw new JADESecurityException(bpe.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (IllegalBlockSizeException ike){
			throw new JADESecurityException(ike.getMessage());
		}
	}

	/**
	 * Encrypts the given text with the given asymmetric key and algorithm
	 */
	private byte[] asymEncrypt(byte[] text, JADEPrincipal key) throws JADESecurityException{
		try{
			// creation of the cipher
			Cipher cipher = Cipher.getInstance(key.getSDSIName().getAlgorithm());

			// initialize the cipher
			cipher.init( Cipher.ENCRYPT_MODE, publicKeyFromBytes(key) );

			int blockSize = cipher.getBlockSize();
			myLogger.log(Logger.FINE, "Asymmetric encryption: payload-length = "+text.length+", algorithm = "+cipher.getAlgorithm()+", block-size "+cipher.getBlockSize());
			int position = 0;
			ByteArrayOutputStream encryptedBytes = new ByteArrayOutputStream();
			while (position < text.length) {
				int length;
				int numberOfBytesLeftToEncrypt = text.length - position;
				if (blockSize > 0 && blockSize <= numberOfBytesLeftToEncrypt) {
					length = blockSize;
				} 
				else {
					length = numberOfBytesLeftToEncrypt;
				}	
				encryptedBytes.write(cipher.doFinal(text, position, length));
				position += length;
			} 
			return encryptedBytes.toByteArray();
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (NoSuchPaddingException nspe){
			throw new JADESecurityException(nspe.getMessage());
		} catch (BadPaddingException bpe){
			throw new JADESecurityException(bpe.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (IllegalBlockSizeException ike){
			throw new JADESecurityException(ike.getMessage());
		} catch (IOException ie){
			throw new JADESecurityException(ie.getMessage());
		} 
	}

	/**
	 * Decrypts the given text with the given asymmetric key and algorithm
	 */
	private byte[] asymDecrypt(PrivateKey pk, byte[] text) throws JADESecurityException{
		try{
			// creation of the cipher
			Cipher cipher = Cipher.getInstance(pk.getAlgorithm());

			// initialisation of the cipher
			cipher.init(Cipher.DECRYPT_MODE, pk);

			int blockSize = cipher.getBlockSize();
			myLogger.log(Logger.FINE, "Asymmetric decryption: payload-length = "+text.length+", algorithm = "+cipher.getAlgorithm()+", block-size "+cipher.getBlockSize());
			int position = 0;
			ByteArrayOutputStream decryptedBytes = new ByteArrayOutputStream();
			while (position < text.length) {
				int length;
				int numberOfBytesLeftToDecrypt = text.length - position;
				if (blockSize > 0 && blockSize <= numberOfBytesLeftToDecrypt) {
					length = blockSize;
				} else {
					length = numberOfBytesLeftToDecrypt;
				}
				decryptedBytes.write(cipher.doFinal(text, position, length));
				position += length;
			} 
			return decryptedBytes.toByteArray();
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (NoSuchPaddingException nspe){
			throw new JADESecurityException(nspe.getMessage());
		} catch (BadPaddingException bpe){
			throw new JADESecurityException(bpe.getMessage());
		} catch (InvalidKeyException ike){
			throw new JADESecurityException("Invalid Key");
		} catch (IllegalBlockSizeException ike){
			throw new JADESecurityException(ike.getMessage());
		} catch (IOException ie){
			throw new JADESecurityException(ie.getMessage());
		} 
	}


	/**
	 * Verify signature with the own public key
	 * NL: Do we really need this methid? What is the use case?
	 */
	/*
  public boolean verifySignature(byte[] text, byte[] signature) throws Exception {
    return verifySignature(text,signature,getPublic());
  }
	 */

	/**
	 * Converts an encoded public key into its Java object representation
	 */
	private static PublicKey publicKeyFromBytes(JADEPrincipal k) 
	throws JADESecurityException {
		try{
			if ((k==null) || (k.getSDSIName()==null)) throw new JADESecurityException("Null key.");
			// Generate the public key object 
			KeyFactory kf = KeyFactory.getInstance(k.getSDSIName().getAlgorithm());
			KeySpec encKey = new X509EncodedKeySpec(k.getSDSIName().getEncoded());
			return kf.generatePublic(encKey);
		} catch (NoSuchAlgorithmException nsae){
			throw new JADESecurityException(nsae.getMessage());
		} catch (InvalidKeySpecException ikse){
			throw new JADESecurityException(ikse.getMessage());
		}
	}

	/**
	 * Converts an encoded private key into its Java object representation
	 */
	/*
    private PrivateKey privateKeyFromBytes(byte[] encodedKey, String algorithm) throws JADESecurityException {
    // TODO ???
    return null;
    }
	 */

	/**
	 * Converts an encoded secret key into its Java object representation
	 */
	private static SecretKey secretKeyFromBytes(byte[] encodedKey, String algorithm) throws JADESecurityException{
		// Generates the private key object
		return new SecretKeySpec(encodedKey, algorithm);
	}

	/**
	 * Returns this authority's principal which wraps the public key
	 */
	public JADEPrincipal getJADEPrincipal() {
		return myPrincipal;
	}

	/*
	public void verify(JADECertificate cert) throws JADESecurityException {
  }

	public void sign(JADECertificate certificate) throws JADESecurityException {
  }
	 */



} //AuthorityImpl
