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

package jade.core.security;

//#MIDP_EXCLUDE_FILE


import jade.core.Service;

/**

   The horizontal interface for the JADE kernel-level service managing
   security permission checks.

   @author Giosue Vitaglione - Telecom Italia LAB

   @see jade.core.security.SecurityService
*/
public interface SecuritySlice extends Service.Slice {


    /**
       The name of this service.
    */
    public static final String NAME = "jade.core.security.Security";


    // vertical commands
    static final String DO_THAT = "Just-an-example";

    // Constants for the names of horizontal commands associated to methods
    static final String H_COMMAND_1 = "1";
    static final String H_COMMAND_2 = "2";


}
