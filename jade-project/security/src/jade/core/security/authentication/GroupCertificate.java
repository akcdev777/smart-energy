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

import jade.security.JADEPrincipal;
import jade.security.Credentials;
import jade.security.impl.BasicCertificateImpl;
import jade.security.util.CredentialsEngine;

import java.io.*;

/**
 * @author Giosue Vitaglione - TILAB
 * @author Nicolas Lhuillier - Motorola (encoding/decoding)
 * @version $Date: 2004-07-30 12:07:18 +0200 (ven, 30 lug 2004) $ $Revision: 477 $
 */

public class GroupCertificate extends BasicCertificateImpl {

  private JADEPrincipal group = null;

  // required for encoding/decoding
  public GroupCertificate() {
  }

  public GroupCertificate ( JADEPrincipal group ) {
    this.group=group;
  }
  
  public JADEPrincipal getOwner() { return group; }
  
  public String toString() {
    return super.toString() + encodePrincipal(group);
  }

  // ********************************
  // Customized encode/decode methods
  // ********************************
  
  public byte[] encode() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Writes the group principal
    byte[] tmp = CredentialsEngine.encodePrincipal(group);
    out.writeInt(tmp.length);
    out.write(tmp,0,tmp.length);
    // Write the rest of the certificate
    tmp = super.encode();
    out.write(tmp,0,tmp.length);
    // Flush
    return baos.toByteArray();
  }

  public Credentials decode(byte[] enc) throws IOException {
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
    // Decodes the group Principal
    int size = in.readInt();
    byte[] data = new byte[size];
    in.read(data,0,size);
    group = CredentialsEngine.decodePrincipal(data);


    // Decode the rest of the certificate
    int n_left = in.available();
    data = new byte[n_left];
    in.read(data, 0, n_left);
    super.decode(data);

    return this;
  }

}
