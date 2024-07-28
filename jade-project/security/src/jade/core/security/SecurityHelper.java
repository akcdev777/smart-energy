/**
 * ***************************************************************
 * JADE - Java Agent DEvelopment Framework is a framework to develop
 * multi-agent systems in compliance with the FIPA specifications.
 * Copyright (C) 2000 CSELT S.p.A.
 *
 * GNU Lesser General Public License
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 * **************************************************************
 */
package jade.core.security;

import jade.core.Agent;
import jade.core.Profile;
import jade.core.security.authentication.UserPassCredential;
import jade.domain.FIPAAgentManagement.Envelope;
import jade.domain.FIPAAgentManagement.Property;
import jade.domain.FIPAAgentManagement.SecurityObject;
import jade.lang.acl.ACLMessage;
import jade.security.Credentials;
import jade.security.JADEAuthority;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.security.SecurityFactory;
import jade.security.util.CredentialsEngine;
import jade.security.util.SecurityData;
import jade.util.Logger;
import jade.util.leap.Iterator;

import java.io.IOException;
import java.util.Hashtable;

import org.apache.commons.codec.binary.Base64;

/* 
 *  Note: this class shall not make any reference (e.g. import) to any 
 *  java.security.XXX or javax.crypto.XXX to be compatible with all Java editions.
 */

/**
 * This class provides an agent all methods for accessing security functionalities.
 * 
 * Usually each agent has a <code>SecurityHelper</code> object accessible through
 * the <code>getHelper()</code> method of the <code>Agent</code> class.
 *
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @author Nicolas Lhuillier - Motorola 
 * @author Jerome Picault - Motorola 
 * @version  $Date: 2007-04-24 16:20:28 +0200 (mar, 24 apr 2007) $ $Revision: 1001 $
 */
public class SecurityHelper
implements jade.core.ServiceHelper, 
jade.security.CredentialsHelper {

	private Logger myLogger = Logger.getMyLogger(this.getClass().getName());

	// The agent "owning" this SecurityServiceExecutor
	//private Agent myAgent = null;
	private Profile myProfile = null;

	// The authority that performs the actual cryptographic operations
	private JADEAuthority authority = null;

	// Table of trusted external agents (public keys)
	private Hashtable keyring;

	// folder containing the obtained Credentials
	private Credentials credsFolder = null;

	// Constant for setting parameters
	public static final String ASYM_ALGO_KEY = "jade_security_AsymAlgorithm";
	public static final String ASYM_ALGO_DEFAULT = "RSA";
	public static final String ASYM_KEYSIZE_KEY = "jade_security_AsymKeySize";
	public static final String ASYM_KEYSIZE_DEFAULT = "512";
	public static final String SYM_ALGO_KEY = "jade_security_SymAlgorithm";
	public static final String SYM_ALGO_DEFAULT = "AES";
	public static final String SYM_KEYSIZE_KEY = "jade_security_SymKeySize";
	public static final String SYM_KEYSIZE_DEFAULT = "128"; // or 192,256
	public static final String SIGN_ALGO_KEY = "jade_security_SignAlgorithm";
	public static final String SIGN_ALGO_DEFAULT = "SHA1withRSA"; 

	// Constant for credential user-defined parameter in ACLMessage
	public static final String CREDENTIALS = "credentials";


	// Algorithm parameters and default values
	private String  symAlgo;
	private int     symKeySize; 
	private String  signAlgo;


	// constructor
	public SecurityHelper (Profile p){
		this.myProfile=p;
	}

	/**
	 * This must be called in order to initialize the SecurityHelper.
	 * Configuration parameters are read from the profile.
	 */
	public void init(Agent a) {
		setCryptoParameters();
		String name=null;
		try {
			myLogger.log(Logger.FINEST,"SecurityHelper: init(Agent) ");
			keyring = new Hashtable();
			// Creates the authority
			authority = SecurityFactory.getSecurityFactory().newJADEAuthority();

			if (a.getAID()!= null) { 
				name = a.getAID().getName();
			}
			authority.init(name, 
					myProfile, 
					new UserPassCredential("", "".getBytes()) ); // TOFIX: Use real credentials
		}
		catch(Exception e) {
			myLogger.log(Logger.WARNING,"SecurityHelper: Exception occured in init(Agent): "+e);
			e.printStackTrace();
		}

		/*
      try {
      setSymAlgorithm(myAgent.getProperty("jade.security.SymEncryptionAlgorithm",
      "DES" ));  // default is DES
      setDigestAlgorithm(myAgent.getProperty("jade.security.DigestAlgorithm",
      "MD5" ));   // default is MD5
      algoParams = symCipher.getParameters();
      } 
      catch (Exception e) {
      e.printStackTrace();
      }
		 */ 
	}

	private void setCryptoParameters(){
		symAlgo = myProfile.getParameter( SYM_ALGO_KEY, SYM_ALGO_DEFAULT);
		symKeySize = Integer.parseInt( myProfile.getParameter(SYM_KEYSIZE_KEY, SYM_KEYSIZE_DEFAULT) );
		signAlgo = myProfile.getParameter( SIGN_ALGO_KEY, SIGN_ALGO_DEFAULT);
	}

	/**
	 * The SecurityHelper loads keys and certificates of a user
	 * from the default long-term storage.
	 *
	 * If the long-term storage does not contain keys nor certificates for this user
	 * a new key pair is created and stored, so that the same key pair will
	 * be available next time.
	 *
	 * This can be called just after the agent is created,
	 * or in other special cases.
	 *
	 * Example:
	 *   SecurityHelper sh = ...
	 *   sh.init( "alice", pass );  // provides credential
	 *   sh.init( agent );      // normal initialization follows
	 *   ...
	 */
	/*
  public void init(String username, byte[] password) {
    myLogger.log(Logger.FINEST,"sh: loadSecurityStore(.,.)");
    SecurityStore securityStore = new SecurityStore( username );
    securityStore.open( password );
    if ( !securityStore.hasMyKeyPair() ) ;

    // create a JADEAuthority object (for asymmetric encryption & sugnature)
    // that is the Authority wrapped by this SecurityHelper
    authority = (JADEAuthorityImpl) createAuthority(securityStore);

    securityStore.close();
  }
	 */

	/**
	 * Tells if a message has been set with setUseSignature, 
	 * or if an incoming message has been signed by the sender. 
	 * Note that if the incoming message was signed 
	 * then it also means the signature is valid.
	 * @param msg the message to be checked for signature
	 * @return true if message has been signed, false otherwise 
	 */
	public boolean getUseSignature(ACLMessage msg) {
		Envelope e = msg.getEnvelope();
		if (e != null) {
			for (Iterator it = e.getAllProperties(); it.hasNext();) {
				Property p = (Property) it.next();
				if (p.getName().equals(SecurityObject.NAME)) {
					SecurityObject[] so = (SecurityObject[])p.getValue();
					for (int i=so.length-1;i>=0;i--) {
						if (so[i].getType() == SecurityObject.SIGN) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}


	/**
	 * Sets the message to be signed
	 */
	public void setUseSignature(ACLMessage msg) {
		//Currently the information is set to a user defined slot
		Envelope e = msg.getEnvelope();
		if (e == null) {
			e = new Envelope();
			msg.setEnvelope(e);
		}
		SecurityObject[] sos = null;
		for (Iterator it = e.getAllProperties(); it.hasNext();) {
			Property p = (Property) it.next();
			if (SecurityObject.NAME.equals(p.getName())) {  
				SecurityObject[] tmp = (SecurityObject[])p.getValue();
				sos = new SecurityObject[tmp.length+1];
				System.arraycopy(tmp,0,sos,0,tmp.length);
				p.setValue(sos);
				break;
			}
		}
		if (sos == null) {
			sos = new SecurityObject[1];
			e.addProperties(new Property(SecurityObject.NAME,sos));
		}
		SecurityObject so = new SecurityObject(SecurityObject.SIGN);
		SecurityData sd = new SecurityData();
		so.setEncoded(sd);
		//sd.key = getKey(); //No longer set the key here
		sd.algorithm = signAlgo;
		/*
      try {
      encode(so,sd); // NL: should not encode here for better performance
      }
      catch(Exception ex) {
      System.err.println(ex);
      //NL: Should not happen
      }
		 */
		sos[sos.length-1] = so; 
	}

	/**
	 * Tells if a message has been set with setUseEncryption, 
	 * or if an incoming message has been encrypted by the sender.
	 */
	public boolean getUseEncryption(ACLMessage msg) {
		Envelope e = msg.getEnvelope();
		if (e != null) {
			for (Iterator it = e.getAllProperties(); it.hasNext();) {
				Property p = (Property) it.next();
				if (p.getName().equals(SecurityObject.NAME)) {
					SecurityObject[] so = (SecurityObject[])p.getValue();
					for (int i=so.length-1;i>=0;i--) {
						if (so[i].getType() == SecurityObject.ENCRYPT) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	/**
	 * Sets the message to be encrypted.
	 */
	public void setUseEncryption(ACLMessage msg) {
		Envelope e = msg.getEnvelope();
		if (e == null) {
			e = new Envelope();
			msg.setEnvelope(e);
		}
		SecurityObject[] sos = null;
		for (Iterator it = e.getAllProperties(); it.hasNext();) {
			Property p = (Property) it.next();
			if (SecurityObject.NAME.equals(p.getName())) {
				SecurityObject[] tmp = (SecurityObject[])p.getValue();
				sos = new SecurityObject[tmp.length+1];
				System.arraycopy(tmp,0,sos,1,tmp.length);
				p.setValue(sos);
				break;
			}
		}
		if (sos == null) {
			sos = new SecurityObject[1];
			e.addProperties(new Property(SecurityObject.NAME,sos));
		}
		SecurityObject so = new SecurityObject(SecurityObject.ENCRYPT);
		SecurityData sd = new SecurityData();
		so.setEncoded(sd);
		sd.algorithm = symAlgo;
		sd.size = symKeySize;
		/*
      try {
      encode(so,sd); // NL: should not encode here for better performance
      }
      catch(Exception ex) {
      System.err.println(ex);
      //NL: Should not happen
      }
		 */
		sos[0] = so; 
	}


	/**
	 * Adds the public key k for agent a to the keyring of trusted public keys
	 * TODO: This is a problem as it is not sure at all that the key is trusted!!
	 */
	public void addTrustedPrincipal(JADEPrincipal k) {
		if (k != null) {
			keyring.put(k.getName(),k);
		}
	}

	/**
	 * Returns the public for the given agent if known and trusted
	 * and null otherwise
	 */
	public JADEPrincipal getTrustedPrincipal(String name) {
		return (JADEPrincipal)keyring.get(name);
	}

	/**
	 *  Sets the algorithm to be used for symmetric encryption and decryption.
	 *  Examples of valid transformations are:
	 *	 - "DES"
	 *   - "AES"
	 *   - "PBEWithMD5AndDES"
	 *   - "DES/ECB/PKCS5Padding"
	 */
	public void setSymmetricAlgorithm(String a) {
		symAlgo = a;
	}

	/**
	 * Returns the algorithm currently set for symmetric encryption/decription.
	 */
	public String getSymmetricAlgorithm() {
		return symAlgo;
	}

	/**
	 * Sets the strength of the symmetric encryption key.
	 * Note: this must be compliant with the symmetric algorithm
	 * @see setSymmetricAlgorithm
	 */
	public void setKeySize(int s) {
		symKeySize = s;
	}

	/**
	 * Returns the strength of the symmetric key used for encryption.
	 */
	public int getKeySize() {
		return symKeySize;
	}

	/**
	 * Sets the algorithm to be used for signing.
	 * Valid algorithms depend on the 
	 */
	public void setSignatureAlgorithm(String a) {
		signAlgo = a;
	}

	/**
	 * Returns the algorithm currently in use for signature.
	 */
	public String getSignatureAlgorithm() {
		return signAlgo;
	}


	/**
	 *  Set the parameters to be used with the symmetric algorithm
	 */
	/*
  public void setSymParameters(byte[] encodedParameters) {
    try{

      algoParams = AlgorithmParameters.getInstance(
                                                   symCipher.getAlgorithm()
                                                   );
      algoParams.init( encodedParameters );

    } catch (Exception e) { e .printStackTrace(); }
  }
	 */

	/**
	 *  Get the configuration (agent-scoped)
	 *	for symmetric encription and decription.
	 */
	/*
  public byte[] getSymParameters() {
    AlgorithmParameters algParams=null;
    byte[] retVal=null;
    try{
	    algoParams = symCipher.getParameters();
	    retVal = algoParams.getEncoded();
    } catch (Exception e) { e.printStackTrace(); }
    return retVal;
  }
	 */

	/**
	 * Encrypt the given text by using information of the Security Object
	 * and updates the informations in the Security object
	 * @param so the Security Object used to encrypt the text
	 * @param text the text to be encrypted
	 * @param receiver the receiver of the encrypted text
	 * @return the encrypted text
	 */
	/*
  public byte[] encrypt(SecurityObject so, byte[] text, AID receiver) throws Exception {
    SecurityData sd = decode(so);
    // retrieve the receiver's public key
    JADEKey recKey = getTrustedKey(receiver);
    if (recKey == null) { 
      // the receiver'k public key is not known
      throw new Exception("Unknown receiver's public key");
    }
    byte[] enc = authority.encrypt(sd,text,recKey);
    // re-encode so
    encode (so, sd);          
    // returns the encrypted text
    return enc;
  }
	 */

	/**
	 * Decrypts the given text by using information of the Security Object
	 * @param so the Security Object used to encrypt the text
	 * @param text the text to be encrypted
	 * @return the decrypted text
	 */
	/*
  public byte[] decrypt(SecurityObject so, byte[] enc) throws Exception{
    SecurityData sd = decode(so);
    return authority.decrypt(sd,enc);
  }
	 */

	/**
	 *     Calculate the message digest (aka the hash) of the given text.
	 *     The algorithm used is set by
	 */
	/*
  public byte[] digest(byte[] text) {
    try {
	    MessageDigest md5 = MessageDigest.getInstance(digestAlgorithm);
	    return md5.digest(text);
    } catch (NoSuchAlgorithmException e) { e.printStackTrace();
    }
    return null;
  }

  public void setDigestAlgorithm (String algorithm) {
    // it should be checked if it is a valid one
    digestAlgorithm = algorithm;
  }
	 */

	/**
	 * Returns the principal of this SecurityHelper
	 */
	public JADEPrincipal getPrincipal() {
		// returns the Principal related to this SH
		return authority.getJADEPrincipal();
	}


	/**
	 *  Returns the principal of an agent in the local platform
	 *  with the given local name.
	 */
	public JADEPrincipal getPrincipal(String name) {
		JADEPrincipal result = null;
		// First: look in the keyring
		result = getTrustedPrincipal(name);
		// Second: if this fails, search the platform cache
		if (result == null) {
			myLogger.log(Logger.WARNING,"Platform cache is not implemented!");
		}
		return result;
	}

	/**
	 * Returns the principal of an agent in the local platform
	 * with the given AID.
	 */
	/*
  public JADEPrincipal getPrincipal(AID aid) {
		JADEPrincipal p = null;
    myLogger.log( Logger.WARNING, "not implemented!");

    // ask the Platform's CA for the certificate of the agent
    // verify the certificate
    // get the pub.key from the certificate
    // return the pub.key

    return p;
  } // end getPrincipal(AID)
	 */


	/**
	 * Returns the authority that performs the actual cryptographic operations
	 * @see JADEAuthority
	 */
	public JADEAuthority getAuthority(){
		return authority;
	}


	/**
	 * Returns the credentials of the SecurityHelper's Credentials Folder.
	 */
	public Credentials getCredentials() {
		return credsFolder;
	}

	/**
	 * Add new credentials to the Credentials Folder.
	 */
	public void addCredentials( Credentials newCreds ) {
		// it should be checked if the same Credentials is not yet present
		credsFolder = CredentialsEngine.add( credsFolder, newCreds );
	} // end addCredentials





	// ************************************************
	// Implementation of the CredentialHelper interface
	// ************************************************

	/**
	 * If the ACLMessage is signed, this method returns the signer's principal 
	 * contained in the envelope of the message. 
	 * Ohterwise it returns null.
	 */
	public JADEPrincipal getPrincipal(ACLMessage msg) {
		JADEPrincipal k = null;
		Envelope e = msg.getEnvelope();
		if (e != null) {
			SecurityObject so = SecurityService.getSecurityObject(e,SecurityObject.SIGN); 
			if (so != null) {
				try {
					k = ((SecurityData)so.getEncoded()).key;
				}
				catch(ClassCastException cce) {
					// This should not happen
					myLogger.log(Logger.SEVERE,"SecurityObject is not properly decoded!");
				}
			}
		}
		return k;
	} 

	/**
	 * The set of credentials attached to the ACL Message are extracted 
	 * from the :X-credential slot and returned.
	 * If not credentials were attached, this method returns null.
	 */
	public Credentials getCredentials(ACLMessage msg) throws JADESecurityException {
		try {
			// TOFIX: This uses a user-defined slot, to be fixed once FIPA has standardized
			String txt;
			// Decodes the "Credentials" slot
			if ((txt = msg.getUserDefinedParameter(CREDENTIALS)) != null) {
				byte[] tmp = Base64.decodeBase64(txt.getBytes("US-ASCII"));
				// Decodes the Credentials
				return CredentialsEngine.decodeCredentials(tmp);
			}
			return null;
		}
		catch(IOException ioe) {
			myLogger.log(Logger.WARNING,ioe.toString());
			throw new JADESecurityException("IO Exception while decoding Credentials");
		}
	}

	/**
	 * Attach credentials to the :X-credential slot of this ACLMessage.
	 * Developers shall pay attention that if the ACL Message 
	 * already contained credentials,
	 * these will be replaced by the new ones 
	 */
	public void addCredentials(ACLMessage msg, Credentials cred) throws JADESecurityException {
		try {
			// TOFIX: This uses a user-defined slot, to be fixed once FIPA has standardized
			String tmp = new String(Base64.encodeBase64(CredentialsEngine.encodeCredentials(cred)), "US-ASCII");
			msg.addUserDefinedParameter(CREDENTIALS, tmp);
		}
		catch(IOException ioe) {
			myLogger.log(Logger.SEVERE,ioe.toString());
			throw new JADESecurityException("IO Exception while encoding Credentials");
		}
	}


} // end SecurityHelper class

