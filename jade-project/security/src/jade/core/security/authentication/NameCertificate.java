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

/**


   @author Giosue Vitaglione - TILAB
   @version $Date: 2004-07-13 11:47:37 +0200 (mar, 13 lug 2004) $ $Revision: 394 $
 */
public class NameCertificate extends GroupCertificate {
//TOFIX: it would be good having this encoded as X.509 certificate 
  
  // required for encoding/decoding
  public NameCertificate () {
  }

  public NameCertificate ( JADEPrincipal owner ) {
    // the group principal is the user principal
    super(owner);
    setSubject(owner);
  }

  public JADEPrincipal getSubject() { // just to document it clearly
    return super.getSubject(); 
  }

} // end class NameCertificate
