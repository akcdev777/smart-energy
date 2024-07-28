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

package jade.security.util;

import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.SDSIName;
import jade.security.impl.JADEPrincipalImpl;
import jade.security.impl.SDSINameImpl;

import java.io.*;

/**
 * 
   @author Giosue Vitaglione - TILAB
   @version $Date: 2004-09-08 08:51:06 +0200 (mer, 08 set 2004) $ $Revision: 505 $
 */
public class CredentialsEngine  {

  /**
   *   Union of Credentials
   */
  public static Credentials add(Credentials cred1, Credentials cred2){
    CredentialsSet sum = new CredentialsSet();
    sum.add( cred2 );
    sum.add( cred1 );
    return sum;
  } // end add(cred,cred)


  public static Credentials decodeCredentials(byte[] enc) 
    throws IOException {
    try {
      DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
      // Reads "Credential" class
      String credClass = in.readUTF();
      // Reads encoding size
      int size = in.readInt();
      byte[] tmp = new byte[size];
      in.read(tmp,0,size);
      // Calls the decode method of the corresponding instance
      return ((Credentials)Class.forName(credClass).newInstance()).decode(tmp);
    }
    catch(ClassNotFoundException cnfe) {
      throw new IOException("Unsupported Credentials type");
    }
    catch(InstantiationException ie) {
      // This should not occur
      System.out.println(ie);
      throw new IOException("Unexpected Java exception");
    }
    catch(IllegalAccessException iae) {
      // This should not occur
      System.out.println(iae);
      throw new IOException("Unexpected Java exception");
    }
  }
  
  public static byte[] encodeCredentials(Credentials creds) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Writes "Credential" class
    out.writeUTF(creds.getClass().getName());
    // Encodes the creds
    byte[] tmp = creds.encode();
    // Writes encoding size
    out.writeInt(tmp.length);
    // Writes the encoding
    out.write(tmp,0,tmp.length);
    return baos.toByteArray();
  }
  
  
  public static JADEPrincipal decodePrincipal(byte[] enc) throws IOException {
    if (enc.length == 0) {
      return null;
    }
    else {
      DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
      // Reads the principal's name
      String name = in.readUTF();
      String firstString="";
      String algo=null;
      String format=null;
      String[] names=null;
      byte[] data = null;
      int size; 
      
      // Decodes the SDSIName
      firstString = in.readUTF();
      if (!firstString.equals("nullSDSIName") ) {
        // Algorithm
        algo = firstString;
        // Format
        format = in.readUTF();
        // Data
        size = in.readInt();
        data = new byte[size];
        in.read(data, 0, size);
        // Names
        size = in.readInt();
        names = new String[size];
        for (int i = 0; i < size; i++) {
          names[i] = in.readUTF();
        }
      } else {
        // it was a null SDSINameImpl
      }

      return new JADEPrincipalImpl(name, new SDSINameImpl(data,algo,format,names));
    }
  }


  public static byte[] encodePrincipal(JADEPrincipal p) throws IOException {
    if (p == null) {
      return new byte[0];
    }
    else {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(baos);
      // Writes the name
      out.writeUTF(p.getName());

      // Encodes the SDSIName
      SDSIName key = p.getSDSIName();
      if (key!=null) {
      // Writes the algorithm
      out.writeUTF(key.getAlgorithm());
      // Writes the encoding format
      out.writeUTF(key.getFormat());
      // Writes the encoded key
      byte[] tmp = key.getEncoded();
      out.writeInt(tmp.length);
      out.write(tmp,0,tmp.length);
      // Writes the local names
      String[] names = key.getLocalNames();
      out.writeInt(names.length);
      for (int i=0; i<names.length; i++) {
        out.writeUTF(names[i]);
      }
    } else {
      out.writeUTF("nullSDSIName");
    }


      // Flush
      return baos.toByteArray();
    }
  }

  public static SecurityData decodeSignature(byte[] enc) throws IOException {
    if (enc.length == 0) {
      return null;
    }
    else {
      SecurityData sd = new SecurityData();
      DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
      // Reads the algorithm
      sd.algorithm = in.readUTF();
      // Decodes the Principal
      int size = in.readInt();
      byte[] data = new byte[size];
      in.read(data,0,size);
      sd.key = decodePrincipal(data);
      // Decodes the signature
      size = in.readInt();
      data = new byte[size];
      in.read(data,0,size);
      sd.data = data;
      return sd;
    }
  }
  
  public static byte[] encodeSignature(SecurityData sd) throws IOException {
    if (sd == null) {
      return new byte[0];
    }
    else {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(baos);
      // Writes the signature algorithm
      out.writeUTF(sd.algorithm);
      // Writes the principal
      byte[] tmp = encodePrincipal(sd.key);
      out.writeInt(tmp.length);
      out.write(tmp,0,tmp.length); 
      // Writes the signature
      tmp = sd.data;
      out.writeInt(tmp.length);
      out.write(tmp,0,tmp.length); 
      // Flush
      return baos.toByteArray();
    }
  }



} // end CredentialsEngine

