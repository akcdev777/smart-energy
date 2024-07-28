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

package jade.core.security.authentication;

import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.impl.JADEPrincipalImpl;
import java.util.Enumeration;
import java.util.Vector;

import java.io.*;

/**
   @author Giosue Vitaglione - TILAB
   @author Nicolas Lhuillier - Motorola (encoding/decoding)
   @version $Date: 2004-07-13 11:47:37 +0200 (mar, 13 lug 2004) $ $Revision: 394 $
 */

public class UserPassCredential implements Credentials {

  private String username = null;
  private byte[] password;

  // Required for encoding/decoding
  public UserPassCredential () {
  }

  public UserPassCredential (String username, byte[] password ) {
    this.username=username;
    this.password=password;
  }
  public String getUsername() { return username;}
  public void setUsername(String username) {this.username=username; }
  public byte[] getPassword() { return password; }
  public void setPassword(byte[] password) { this.password=password; }

  /**
   * Returns the JADEPrincipal who is the owner of these Credentials
   * @return
   */
  public JADEPrincipal getPrincipal() { return null; }

  public Enumeration elements() {
    Vector v = (new Vector(1));
    v.add(this);
    return v.elements();
  }

  public JADEPrincipal getOwner() {
    return new JADEPrincipalImpl(username);
  }
  
  public byte[] encode() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Write UserName
    out.writeUTF(username);
    // Write Password
    out.write(password.length);
    out.write(password,0,password.length);
    return baos.toByteArray();
  }
  
  public Credentials decode(byte[] enc) throws IOException {
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
    // Reads username
    username = in.readUTF();
    // Reads Password
    int size = in.read();
    password = new byte[size];
    in.read(password,0,size);
    return this;
  }
  
  
}
