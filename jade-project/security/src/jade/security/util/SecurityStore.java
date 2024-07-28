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

package jade.security.util;

import jade.core.Agent;
import jade.lang.acl.ACLMessage;
import jade.domain.FIPAAgentManagement.Envelope;
import jade.domain.FIPAAgentManagement.Property;
import jade.util.leap.*;
import jade.util.Logger;
import jade.security.*;


import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Key;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.KeyStore;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStoreException;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import java.io.*;
import java.util.Hashtable;
import jade.core.Profile;
import jade.core.ProfileImpl;
import jade.security.impl.SDSINameImpl;
import jade.security.Name;
import java.util.Enumeration;
import jade.security.impl.JADEPrincipalImpl;

/**
 * This class provides a mean for storing security-related information,
 * such as a key pair and a set of certificates.
 *
 * A SecurityStore can contain:
 *
 *  - getMyKeyPair()    (an asymmetric key pair)
 *  - getMySelfCertificate()  (a self-signed certificate of the pair above)
 *  - getPrincipal(String alias) (works a storage of couples: string<->Principal
 *  - setPrincipal(String alias, JADEPrincipal)
 *  - ...?
 *
 *  This implementation uses internally a java KeyStore object.
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @version  $Date: 2010-04-19 16:16:43 +0200 (lun, 19 apr 2010) $ $Revision: 1761 $
 */
public class SecurityStore {

  private static Logger myLogger = Logger.getMyLogger(SecurityStore.class.getName());
  
  private String username = "";
  private byte[] password;
  
  // main asymetric key pair
  private KeyPair keypair = null;
  
  // repository of JADEPrincipals
  private Hashtable principals = new Hashtable();
  
  // certificates and keys
  // Temporary removed by NL
  //private KeyStore keystore = null;
  
  
  private String name = "";
  private static String dirName = "Security/";
  private static String ext = ".keystore";
  private static String ext_map = ".map";
  
  public static String getDirName(){return dirName;}
  public static String getFileExtension(){return ext;}
  
  public SecurityStore (String user) {
    this.username = user;
    
    name = username;
    
    // Create an empty keystore object
    // Removed by NL
    /*
      try {
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(null, null);
      }
      catch (java.security.KeyStoreException e) {e.printStackTrace();}
      catch (java.io.IOException e) {e.printStackTrace();}
      catch (NoSuchAlgorithmException e) {e.printStackTrace();}
      catch (java.security.cert.CertificateException e) {e.printStackTrace();}
    */ 
  } // end constructor
    
    
  /**
   *  Create a new key pair and put it into the SecurityStore.
   *  If there was already one, the newly created replaces the existing pair.
   * 
   */
  public void generateNewMyKeyPair(int asymKeySize, String asymAlgo) {
    keypair=generateNewKeyPair(asymKeySize, asymAlgo);
    setMyKeyPair( keypair );
  }

  /**
   * Generate a key pair, given the key size and the algorithm to be used.
   * @return
   */
  public static KeyPair generateNewKeyPair(int asymKeySize, String asymAlgo) {
    KeyPair keypair=null;
    try {

      // instantiate a random number generator
      // random number generator
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(System.currentTimeMillis());

      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(asymAlgo);  //,asymProvider);
      keyPairGen.initialize(asymKeySize, random);
      myLogger.log(Logger.FINEST,"Generating new key pair...");
      keypair = keyPairGen.generateKeyPair();

      myLogger.log(Logger.FINEST,"Key pair generated: " +
                   keypair.getPrivate().getEncoded() + " - " +
                   keypair.getPublic().getEncoded());
    }
    catch (NoSuchAlgorithmException e) {
      myLogger.log(Logger.WARNING, e.toString());
      e.printStackTrace();
    }

    return keypair;

  } // end setNewKeyPair


  /**
   * @return
   */
  public boolean hasMyKeyPair() {
    /*
      boolean ret = false;
      try {
      if (new File(dirName + name + ext).exists()){
      getMyKeyPair();
      ret = ( 
      (keypair!=null) && ( keypair.getPublic()!=null)
      );
      } // end if
      }
      catch (Exception e) {
      e.printStackTrace();
      }
      return ret;
    */
    // Temporary hack by NL
    return (keypair != null);
  }
  

  // reopen the SecurityStore
  public void open (byte[] password) {
    open(username, password);
  } // end open

  // open the SecurityStore
  public void open (String username, byte[] password) {
    myLogger.log(Logger.FINEST,"SecurityStore.open(): "+username);
    this.username = username;
    this.password = password;

    // retrieve the keypair
    /*    try {
          keystore.load(null, new String(password).toCharArray() );
          if (new File(dirName+name+ext).exists() ) { // does it exist a file of a KeyStore?
          // Load the keystore contents
          FileInputStream in = new FileInputStream( dirName+name+ext );
          keystore.load(in, new String(password).toCharArray() );
          in.close();
          } // if the file does not exist, do nothing more
          } catch (Exception e) { e.printStackTrace(); }
    */

    // retrieve the keypair (from a cleartext file)
    /*
      // Changed by NL: does not use the file yet
      try {
      if (new File(dirName + name + ext).exists()) { // does the file exist ?
      // load keypair
      FileInputStream in = new FileInputStream(dirName + name + ext);
      ObjectInputStream oos = new ObjectInputStream(in);
      keypair = (KeyPair) oos.readObject();
      in.close();
      } // if the file does not exist, do nothing more
      }
      catch (Exception e) {
      e.printStackTrace();
      }


      try {
      if (new File(dirName+name+ext_map).exists() ) { // does the file exist ?
      // load principal table
      FileInputStream in = new FileInputStream ( dirName+name+ext_map);
      ObjectInputStream oos = new ObjectInputStream( in );
      principals = (Hashtable) oos.readObject();
      //System.out.println( "Loaded: "+ principals );
      in.close();
      } // if the file does not exist, do nothing more
      } catch (Exception e) { e.printStackTrace(); }
    */

  } // end constructor


  public void close () {
    username = "";
    password = null;
    //keystore = null;
    keypair = null;
    name = "";
  }

  public void flush () {
    flush(password);
  }
  public void flush (byte[] password) {
    myLogger.log(Logger.FINEST,"Flush() is not yet implemented"); 
    /*
      myLogger.log(Logger.FINEST,"SecurityStore.flush():  "+name+"  ");
      if (keystore!=null) {
      try {
      // Save the keystore contents
      // Create the directory
      boolean created = (new File("Security")).mkdirs();
      boolean success = (new File("Security")).isDirectory();
      if (!success) {
      // Directory creation failed
      throw new Exception("Could not create the directory"+dirName);
      }
      FileOutputStream out = new FileOutputStream( dirName+name+ext );
        
      //The whole keystore shold be stored into a file
      //keystore.store(out, new String(password).toCharArray() );
      out.write( o2ba(keypair) );
      out.close();

      // flush principal table
      FileOutputStream out2 = new FileOutputStream( dirName+name+ext_map );
      out2.write( o2ba(principals) );
      out2.close();

      myLogger.log(Logger.FINEST," DONE!");
      } catch (NoSuchAlgorithmException e) { e.printStackTrace();
      } catch (KeyStoreException e) { e.printStackTrace();
      } catch (IOException e) { e.printStackTrace();
      } catch (Exception e) { e.printStackTrace();
      }
      }
    */
  } // end flush



  private byte[] o2ba(Object o) {
    byte[] ka=null;
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(o);
      ka = baos.toByteArray();
      //System.out.println(new String(ka));
    } catch (Exception e) { e.printStackTrace(); }
    return ka;
  }
  private Object ba2o(byte[] ba) {
    Object o=null;
    try {
      ByteArrayInputStream baos = new ByteArrayInputStream( ba );
      ObjectInputStream oos = new ObjectInputStream( baos );
      o = oos.readObject();
      //System.out.println( o );
    } catch (Exception e) { e.printStackTrace(); }
    return o;
  }



  // retrieve the principal of the user "owning" this KeyStore
  public JADEPrincipal getMyPrincipal() {
    if (hasMyKeyPair()) {
      PublicKey k = getMyKeyPair().getPublic(); 
      return new JADEPrincipalImpl(username, 
                                   new SDSINameImpl(k.getEncoded(),k.getAlgorithm(),k.getFormat()));
    } 
    else {
      return new JADEPrincipalImpl(username);
    }
  } // end getMyPrincipal()
  
  public KeyPair getMyKeyPair() {
    /*
      String priKeyAlias = username+"-private";
      String pubKeyAlias = username+"-private";
      PrivateKey privateKey=null;
      PublicKey publicKey=null;
      if (keystore != null) {
      try {
      if (keystore.isKeyEntry( priKeyAlias ) ) {
      privateKey = (PrivateKey) keystore.getKey( priKeyAlias, new String(password).toCharArray() );
      //
      if (privateKey instanceof PrivateKey) {
      // Get certificate of public key
      java.security.cert.Certificate cert = keystore.getCertificate(pubKeyAlias);
      // Get public key
      publicKey = cert.getPublicKey();
      }
      //
      }
      if (keystore.isKeyEntry( pubKeyAlias ) ) {
      publicKey = (PublicKey) keystore.getKey( pubKeyAlias, new String(password).toCharArray() );
      }
      keypair = new KeyPair(publicKey, privateKey );
      }
      catch (KeyStoreException e) { e.printStackTrace(); }
      catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
      catch (UnrecoverableKeyException e) { e.printStackTrace(); }
      }
    */
    return keypair;
  } // end getMyKeyPair()


  /**
   * Set 'my' keypair 
   * 
   * @return
   */
  public KeyPair setMyKeyPair(KeyPair kp) {

    // memorize the keypair
    keypair=kp;
    /*
      //insert the keypair into the keystore
      String priKeyAlias = username+"-private";
      String pubKeyAlias = username+"-private";
      if (keystore != null) {
      try {
      //CertificateFactory cf = CertificateFactory.getInstance("X.509");
      //Certificate cert = cf.generateCertificate();
      PrivateKey privateKey = kp.getPrivate();
      PublicKey publicKey = kp.getPublic();
      char[] pw = new String(password).toCharArray();
      keystore.setKeyEntry( priKeyAlias, privateKey, pw, null);
      keystore.setKeyEntry( pubKeyAlias, publicKey, pw, null);
      } catch (KeyStoreException e) { e.printStackTrace(); }    }
    */
    return keypair;
  } // end setMyKeyPair()

  public void setPrincipal(String alias, JADEPrincipal p) {
    try {
      principals.put(p, alias);
    } 
    catch (Exception e){e.printStackTrace();}
  }

  public Name[] getLocalNames( JADEPrincipal p ) {
    try {
      //System.out.println( "p.getName()="+p.getName()+"     Hashcode = "+p.hashCode());
      if (p==null) return null;
      
      String locname = (String) principals.get( p );
      Name[] result = null;
      if (locname!=null) {
        Name.getName( new String[] {locname} );
      }
      return result;
      
    } catch (Exception e){e.printStackTrace();}
    return null;
  } // end getPrincipal

  public JADEPrincipal getPrincipal(String alias) {
    JADEPrincipal retVal=null;
    try {
      //@@@    TO TEST
      Enumeration it = principals.keys();
      boolean found = false; 
      while ( (it.hasMoreElements()) && (!found) ) {
        // Get value
        Object key = it.nextElement();
        String a1 = (String) principals.get( key );
        if (alias.equals( a1 )) { found=true; retVal=(JADEPrincipal)key; }
      }
    } catch(Exception e) {e.printStackTrace(); }
    return retVal;
  } // end getPrincipal
  
  public java.util.Enumeration getAllPrincipals() {
    return principals.keys();
  }
} // end class

