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
import javax.security.auth.login.LoginException;

/**
*	The <code>JADEUserAuthenticator</code> interface represents the
*    entity that takes as input a couple: username/password
*    and must provide:
*       - the JADEPrincipal associated (if present, also with SDSIName)
*       - and Credentials (if any) owned by that user at start-up time.
*
*
*    @author Giosue Vitaglione - Telecom Italia LAB
*    @version $Date: 2004-07-13 11:47:37 +0200 (mar, 13 lug 2004) $ $Revision: 394 $
*/
public interface JADEUserAuthenticator {

  /**
   *
   */
  public void login( ) throws LoginException, SecurityException;
  public void login( Credentials cred ) throws LoginException, SecurityException;
  public jade.security.JADEPrincipal getPrincipal();
  public jade.security.Credentials getCredentials();

}
