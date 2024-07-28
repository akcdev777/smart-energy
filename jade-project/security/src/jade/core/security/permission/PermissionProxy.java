/*****************************************************************
JADE - Java Agent DEvelopment Framework is a framework to develop
multi-agent systems in compliance with the FIPA specifications.
Copyright (C) 2000 CSELT S.p.A.

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

package jade.core.security.permission;

//#MIDP_EXCLUDE_FILE

import jade.core.Service;
import jade.core.security.authentication.NameCertificate;
import jade.security.JADEPrincipal;
import jade.core.GenericCommand;
import jade.core.Node;
import jade.core.IMTPException;
import jade.core.NotFoundException;
import jade.core.NameClashException;
import jade.security.JADESecurityException;
import jade.core.ServiceException;
import jade.core.security.authentication.OwnershipCertificate;

/**

   The remote proxy for the JADE kernel-level service managing
   the permission-related functionalities.

   @author Giosue Vitaglione - Telecom Italia LAB
*/
public class PermissionProxy extends Service.SliceProxy implements PermissionSlice {

  public NameCertificate getNameCertificate(JADEPrincipal principal) {
    return getNameCert( principal );
  }

  public NameCertificate getNameCertificate(String name) {
    return getNameCert( name );
  }

  // create and send the h.cmd, get a result NameCertificate
  private NameCertificate getNameCert(Object obj) {

    NameCertificate nameCert=null;
    try {
      // create H_CMD
        GenericCommand hcmd = new GenericCommand(NAMECERT_REQ, PermissionService.NAME, null);
        hcmd.addParam( obj );

        Node n = getNode();
        Object result = null;
        try {
          // send the h-cmd and get a response
          result = n.accept(hcmd);
        } catch (IMTPException ex) {
        }
        if((result != null) && (result instanceof Throwable)) {
            if(result instanceof IMTPException) {
                //throw (IMTPException)result;
            } else if(result instanceof NotFoundException) {
                //throw (NotFoundException)result;
            } else if(result instanceof NameClashException) {
                //throw (NameClashException)result;
            } else if(result instanceof JADESecurityException) {
                //throw (JADESecurityException)result;
            } else {
                //throw new IMTPException("An undeclared exception was thrown", (Throwable)result);
            }
        }
        if (result instanceof NameCertificate) nameCert = (NameCertificate) result;
    }
    catch(ServiceException se) {
        //throw new IMTPException("Unable to access remote node", se);
    }
    return nameCert;
  }



  public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned) {
    return getOwnershipCertificate(owned,null);
  }
  public OwnershipCertificate getOwnershipCertificate(String owned) {
    return getOwnershipCert(owned, null);
  }

  public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned, JADEPrincipal owner) {
    return getOwnershipCert(owned, owner);
  }

  private OwnershipCertificate getOwnershipCert(Object owned, JADEPrincipal owner) {
    OwnershipCertificate ownCert=null;
    try {
      // create H_CMD
        GenericCommand hcmd = new GenericCommand(OWNCERT_REQ, PermissionService.NAME, null);
        hcmd.addParam( owned );
        hcmd.addParam( owner );

        Node n = getNode();
        Object result = null;
        try {
          // send the h-cmd and get a response
          result = n.accept(hcmd);
        } catch (IMTPException ex) {
        }
        if((result != null) && (result instanceof Throwable)) {
            if(result instanceof IMTPException) {
                //throw (IMTPException)result;
            } else if(result instanceof NotFoundException) {
                //throw (NotFoundException)result;
            } else if(result instanceof NameClashException) {
                //throw (NameClashException)result;
            } else if(result instanceof JADESecurityException) {
                //throw (JADESecurityException)result;
            } else {
                //throw new IMTPException("An undeclared exception was thrown", (Throwable)result);
            }
        }
        if (result instanceof OwnershipCertificate) ownCert = (OwnershipCertificate) result;
    }
    catch(ServiceException se) {
        //throw new IMTPException("Unable to access remote node", se);
    }
    return ownCert;
  }



} // end PermissionProxy
