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
import jade.security.JADEPrincipal;
import jade.core.security.authentication.NameCertificate;
import jade.core.security.authentication.OwnershipCertificate;

/**

   The horizontal interface for the JADE kernel-level service managing
   security permission checks.

   @author Giosue Vitaglione - Telecom Italia LAB

   @see jade.core.security.permission.PermissionService
   @see jade.core.security.SecurityService
*/
public interface PermissionSlice extends Service.Slice {



    // thrown by other service to announce the security CommandCheckers they
    // want the PermissionService to use for their commands
    //static final String ADD_CHECKERS = "Add-Checkers";

    // Constants for the names of horizontal commands associated to methods
    static final String NAMECERT_REQ = "1";
    static final String OWNCERT_REQ  = "2";
    
    public NameCertificate getNameCertificate( JADEPrincipal principal );
    public NameCertificate getNameCertificate( String name );
    public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned, JADEPrincipal owner);
    public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned);
    public OwnershipCertificate getOwnershipCertificate(String owned);

} // end PermissionSlice
