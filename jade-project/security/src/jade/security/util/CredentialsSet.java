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

import java.util.Enumeration;
import java.io.*;

import jade.security.Credentials;
import java.util.Vector;
import jade.security.JADEPrincipal;
import jade.core.security.SecurityHelper;

/**
 * @author Giosue Vitaglione - TILAB
 * @author Nicolas Lhuillier - Motorola
 * @version $Date: 2004-07-20 15:31:25 +0200 (mar, 20 lug 2004) $ $Revision: 452 $
 */
class CredentialsSet implements Credentials {
  
  private Vector v = new Vector();

    /**
     *  Add more Credentials
     */
    public void add(Credentials cred){
      if (cred!=null) {
        Enumeration en = cred.elements();
        if (en!=null)
        for (; en.hasMoreElements(); ) { // add each of the passed elements
          v.add( (Credentials) en.nextElement());
        }
      }// end if
    }

  // ******************************************
  // Implementation of the Credential interface
  // ******************************************

  public Enumeration elements() {
    return v.elements();
  }
  
  public JADEPrincipal getOwner() {
    JADEPrincipal owner=null;
    Enumeration en = v.elements(); // look into the CredentialSet
    for (; en.hasMoreElements();){
      Credentials c = (Credentials) en.nextElement();
      if (c.getOwner()!=null) {
        owner = c.getOwner();
        break; // take as good the first one
      }
    }// end for
    return owner;
  }
  
  /**
   * Encode the Credentials into a byte array.   
   * The encoding format is:
   * Nb of credentials | (Credential Size | Credential encoding)* 
   */
  public byte[] encode() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Writes nb of children (as a byte)
    int size = v.size();
    out.write(size);
    // Encodes each child
    byte[] tmp;
    for (int i=0; i<size; i++) {
      tmp = CredentialsEngine.encodeCredentials((Credentials)v.elementAt(i));
      // Writes encoding size
      out.writeInt(tmp.length);
      out.write(tmp,0,tmp.length);
    }
    return baos.toByteArray();
  }
  
  /**
   * Encode the Credentials into a byte array.   
   * The encoding format is:
   * Nb of credentials | (Credential class | Encoding size | Encoding)* 
   */
  public Credentials decode(byte[] enc) throws IOException {
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
    // Reads number of chidren
    int s = in.read(); // WARNING: this is a byte actually
    // Decodes all children
    for (int i=0; i<s; i++) {
      // Reads encoding size
      int l = in.readInt();
      // Decodes and adds
      byte[] tmp = new byte[l];
      in.read(tmp,0,l);
      add(CredentialsEngine.decodeCredentials(tmp));
    }
    return this;
  }
}


