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
import jade.core.Filter;
import jade.core.GenericCommand;
import jade.core.IMTPException;
import jade.core.Service;
import jade.core.ServiceException;
import jade.core.messaging.GenericMessage;
import jade.core.messaging.MessagingSlice;
import jade.core.security.SecurityHelper;
import jade.core.security.SecurityService;
import jade.core.security.authentication.OwnershipCertificate;
import jade.security.AuthPermission;
import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.security.MessagePermission;

import java.security.Permission;

/**

    Command checkers for commands related to Messaging Service

   @author Giosue Vitaglione - Telecom Italia LAB

   @see jade.core.security.permission.PermissionService
 */
public class MessagingChecker extends BaseJADEChecker {

	/**
       Perform the authorization check on the received command.
	 */
	public void check(Command cmd) throws JADESecurityException {
		String name = cmd.getName();

		//if (cmd!=null) return; // always return, ---checker disabled---

		//jade.core.security.permission.PermissionFilter.log(direction,  cmd );

		// get data from cmd
		Object[] params = cmd.getParams();

		//      for (int i=0; i<params.length; i++)
		//        System.out.println("     ["+i+"] "+params[i]);

		// prepare parameters for the check
		JADEPrincipal requester = cmd.getPrincipal();
		Credentials creds = cmd.getCredentials();
		Permission permission = null;
		JADEPrincipal target = null; 



		//----------
		if (name.equals(MessagingSlice.SEND_MESSAGE)) {
			AID sender = (AID)params[0];
			GenericMessage msg = (GenericMessage)params[1];
			AID receiver = (AID)params[2];

			// handle failure messages
			if (msg.isAMSFailure()) {
				// Let it pass, it was a FAILURE_NOTIFY converted to SEND_MESSAGE
				// the MessagingService will check: 
				// if this is really a failure => deliver it
				return;
			}

			// handle "sign by defalut" for certain special cases
			String rec = receiver.getLocalName();
			if ( 
					( direction==Filter.OUTGOING) && 
					( 
							(rec.equals( "ams" )) || 
							(rec.equals( "df" ))  
					)) {
				Agent sen = myContainer.acquireLocalAgent(sender);
				try {
					((SecurityHelper)sen.getHelper(SecurityService.NAME)).setUseSignature( msg.getACLMessage() );
				}
				catch (ServiceException ex) { 
					// something went wrong, msg will not be signed
				}
				myContainer.releaseLocalAgent(sender);
			}

			//String ontology= msg.getACLMessage().getOntology();

			String receiverOwner=null;
			OwnershipCertificate oc = (OwnershipCertificate) service.getOwnershipCertificate(receiver.getName());
			if (oc!=null) receiverOwner=oc.getOwner().getName();


			permission = new MessagePermission( 
					MessagePermission.AGENT_NAME+"="+receiver.getName()+AuthPermission.SEP+
					MessagePermission.AGENT_OWNER+"="+receiverOwner 
					, "send-to");
			// add two checks?: AGENT_SEND_AS and AGENT_SEND_FROM

			try {
				checkAction( requester, permission, target, creds);
			} catch(JADESecurityException e) {
				// Issue NotifyFailure vertical command
				try {
					Service ms = myContainer.getServiceFinder().findService(jade.core.messaging.MessagingSlice.NAME);

					// Create a failure message
					GenericCommand failurecmd = new GenericCommand(MessagingSlice.NOTIFY_FAILURE, MessagingSlice.NAME, null  );
					//0- generic message (the same as the blocked one)
					failurecmd.addParam( (GenericMessage) params[1] );
					//1- receiver (is the sender of the message was attempting to go)
					failurecmd.addParam( sender );
					//2- reason why it failed: jade.domain.FIPAAgentManagement.InternalError(String aaa)
					failurecmd.addParam( new jade.domain.FIPAAgentManagement.InternalError("NOT AUTHORIZED") );

					// this failure message should be signed by the local container 
					// since it is "a part" of the ams, and can sing on his behalf.
					// The SignatureFilter has to perform the by getting a special 
					// container's SecurityHelper when the sender is the AMS.

					ms.submit( failurecmd );
				}
				catch (ServiceException ex) {
					// could not send the failure notification
				}
				catch (IMTPException ex) {
					// could not send the failure notification
				}

				// Report authorization exception, normally
				throw e;
			}

		}
		else
			//----------
			if (name.equals(MessagingSlice.DEAD_MTP)) {

				//jade.core.security.permission.PermissionFilter.log( cmd );

				//String agentName = (String) params[0];
				//String className = (String) params[1];

				// permission 
				/*
      permission = new MessagePermission( "class="+className , "create");
      checkAction( requester, 
                   permission, 
                   target, 
                   creds
          );
				 */
			}
			else 
				//----------
				if (name.equals(MessagingSlice.INSTALL_MTP)) {
				}
				else
					//----------
					if (name.equals(MessagingSlice.NEW_MTP)) {
					}
					else
						//----------
						if (name.equals(MessagingSlice.NOTIFY_FAILURE)) {
						}
						else
							//----------
							if (name.equals(MessagingSlice.SET_PLATFORM_ADDRESSES)) {
							}
							else
								//----------
								if (name.equals(MessagingSlice.UNINSTALL_MTP)) {
								}


	} // end method check()

} // end checker class


