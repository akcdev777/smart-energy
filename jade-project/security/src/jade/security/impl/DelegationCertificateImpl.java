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

import jade.security.*;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import jade.security.util.CredentialsEngine;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import jade.util.leap.List;
import jade.util.leap.Iterator;
import java.security.Permission;
import jade.util.leap.ArrayList;

/**
 * This class is the default implementation of DelegationCertificate.
 *
 * @author Giosue Vitaglione - Telecom Italia LAB
 * @version $Date: 2004-07-30 12:11:43 +0200 (ven, 30 lug 2004) $ $Revision: 480 $
 */
 
public class DelegationCertificateImpl
    extends BasicCertificateImpl
    implements DelegationCertificate {

  public DelegationCertificateImpl() {
  }

  public DelegationCertificateImpl(byte[] encoded) throws CertificateException {
    super(encoded);
  }

  // ********************************
  // Customized encode/decode methods
  // ********************************

  public byte[] encode() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Writes the --issuer-- principal (delegator)
    byte[] tmp = CredentialsEngine.encodePrincipal(getIssuer());
    out.writeInt(tmp.length);
    out.write(tmp, 0, tmp.length);
    // --subject-- principal (delegated) is encoded by the super class

    // Writes the delegated permissions
    tmp = encodePermissions(this.getPermissions());
    out.writeInt(tmp.length);
    out.write(tmp, 0, tmp.length);

    // Write the rest of the certificate
    tmp = super.encode();
    out.write(tmp,0,tmp.length);
    // Flush
    return baos.toByteArray();
  }

  public Credentials decode(byte[] enc) throws IOException {
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
    // Decodes the issuer principal
    int size = in.readInt();
    byte[] data = new byte[size];
    in.read(data, 0, size);
    setIssuer( (JADEPrincipal) CredentialsEngine.decodePrincipal(data));
    // --subject-- principal (delegated) is encoded by the super class

    // decode the delegated permissions
    size = in.readInt();
    data = new byte[size];
    in.read(data, 0, size);
    addPermissions( decodePermissions( data ) );

    // Decode the rest of the certificate
    int n_left = in.available();
    data = new byte[n_left];
    in.read(data, 0, n_left);
    super.decode(data);

    return this;
  }

  private byte[] encodePermissions(List perms) {
    Iterator it = perms.iterator();
    StringBuffer sb = new StringBuffer();

    for (; it.hasNext(); ) {
      sb.append(encodePermission( ( (Permission) it.next())));
      sb.append("%");
    }
    return sb.toString().getBytes();
  }

  private List decodePermissions(byte[] encodedPerms) {
    List perms = new ArrayList();

    String[] encodedPerm = new String(encodedPerms).split("%");
    int len=0;
    for (int i=0; i<encodedPerm.length; i++) {
      Permission perm = decodePermission( encodedPerm[i] );
      perms.add( perm );
    }


    return perms;
  }

}