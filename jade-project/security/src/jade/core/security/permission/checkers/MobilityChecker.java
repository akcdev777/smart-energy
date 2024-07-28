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

package jade.core.security.permission.checkers;

import jade.core.AID;
import jade.core.Agent;
import jade.core.Command;
import jade.core.Location;
import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;

import java.security.Permission;

/**

   Command checkers for commands related to Mobility Service

   @author Giosue Vitaglione - Telecom Italia LAB
   @see jade.core.security.permission.PermissionService
*/
public class MobilityChecker extends BaseJADEChecker {

    /**
       Perform the authorization check on the received command.
    */
    public void check(Command cmd) throws JADESecurityException {
    try {
      // get data from cmd
      Object[] params = cmd.getParams();
      AID agentID = (AID)params[0];
      Location where = (Location)params[1];

      for (int i=0; i<params.length; i++)
        System.out.println("     ["+i+"] "+params[i]);

      Agent a = myContainer.acquireLocalAgent(agentID);

      // prepare parameters for the check
      JADEPrincipal subject = null;
      Permission permission = null;
      String action = null;
      JADEPrincipal target = null;
      Credentials creds = null;

      // call the check
      checkAction( subject, permission, target, creds);
      // add two checks: AGENT_MOVE and CONTAINER_MOVE_FROM

      //..Authority.AGENT_MOVE, myContainer.getAgentPrincipal(agentID), a.getCertificateFolder());
      //myContainer.getAuthority().checkAction(Authority.CONTAINER_MOVE_FROM, myContainer.getContainerPrincipal(), a.getCertificateFolder());

    } catch( Exception e) {
        //throw new JADESecurityException(
        System.out.println(
          this.getClass().toString()+": "+
          "Unhandled exception when command type was \""+cmd.getName()+"\""
        );
      e.printStackTrace();
    }
    } // end method check()


} // end checker class


