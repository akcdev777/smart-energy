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
package jade.core.security.permission;

import jade.core.Agent;
import jade.security.Credentials;
import jade.security.JADEAuthority;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.security.PrivilegedExceptionAction;
import jade.security.impl.JADEAuthorityImpl;


/**
 * This class provides an agent all methods for accessing
 * security functionalities related to the permission service.
 *
 *
 * In normal conditions, all agents on a container share the
 * same permissionHelper istance.
 * Agents retrieve the PermissionHelper by using <code>getHelper()</code> method
 * of the <code>Agent</code> class.
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @version  $Date: 2004-07-31 14:52:51 +0200 (sab, 31 lug 2004) $ $Revision: 486 $
 *
 * @see jade.core.Agent#getHelper()
 * @see jade.core.security.permission.PermissionService
 */
public class PermissionHelper implements jade.core.ServiceHelper {


// the agent "owning" this SecurityServiceExecutor
private Agent myAgent = null;

// the default authority
private JADEAuthorityImpl authority = null;


     /**
      *  Helper initialization.
      *  PermissionHelper is not agent-specific, also 'null' can be passed
      * to the init() method.
      */
     public void init(Agent a) {
     } // end init()



     /**
      *  get the default Authority for this Security ServiceManager
      *
      *  The Authority can be used for signing and verifying Certificates
      *
      *  @see Authority
      */
     public JADEAuthority getAuthority() {
       return authority;
     }

     // --- implementation of jade.security.JADEAccessControl ---
     public void checkAction(String action, JADEPrincipal target,
                             Credentials creds) throws JADESecurityException {
     }

     public Object doPrivileged(PrivilegedExceptionAction action) throws Exception {
       return new Object();
     }

     public Object doAsPrivileged(PrivilegedExceptionAction action,
                                  Credentials creds) throws Exception {
       return new Object();
     }

   } // end PermissionHelper class