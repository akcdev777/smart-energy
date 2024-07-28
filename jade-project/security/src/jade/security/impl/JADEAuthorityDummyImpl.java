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

import jade.security.JADEPrincipal;
import jade.util.Logger;
import jade.security.Credentials;
import jade.core.Profile;
import jade.security.util.SecurityData;
import jade.domain.FIPAAgentManagement.SecurityObject;




/**
 * @author Giosue Vitaglione - Telecom Italia LAB
 * @version $Date: 2004-08-24 09:40:52 +0200 (mar, 24 ago 2004) $ $Revision: 502 $
 */
public class JADEAuthorityDummyImpl implements jade.security.JADEAuthority {

  private Logger myLogger = Logger.getMyLogger(this.getClass().getName());
  JADEPrincipal myPrincipal=null; 

  public void init(String authorityName, Profile prof, Credentials creds) {
    myPrincipal = new JADEPrincipalImpl( authorityName );
  }

  public JADEPrincipal getJADEPrincipal() {
    return myPrincipal;
  }

  public SecurityData sign(String algorithm, byte[] text) {
    return null;
  }

  public boolean verifySignature(SecurityData signature, byte[] text) {
    return true;
  }

  public byte[] encrypt(SecurityObject so, byte[] text, JADEPrincipal recKey) {
    return text;
  }

  public byte[] decrypt(SecurityObject so, byte[] enc) {
    return enc;
  }
} // end class JADEAuthorityDummyImpl
