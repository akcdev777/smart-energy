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

package jade.core.security.signature;

//#MIDP_EXCLUDE_FILE

import jade.core.AID;
import jade.core.Agent;
import jade.core.AgentContainer;
import jade.core.BaseService;
import jade.core.Filter;
import jade.core.Profile;
import jade.core.ProfileException;
import jade.core.Service;
import jade.core.ServiceException;
import jade.core.Sink;
import jade.core.VerticalCommand;
import jade.core.messaging.GenericMessage;
import jade.core.messaging.MessagingService;
import jade.core.messaging.MessagingSlice;
import jade.core.security.SecurityHelper;
import jade.core.security.SecurityService;
import jade.core.security.SecuritySlice;
import jade.domain.FIPAAgentManagement.Envelope;
import jade.domain.FIPAAgentManagement.InternalError;
import jade.domain.FIPAAgentManagement.SecurityObject;
import jade.lang.acl.ACLMessage;
import jade.security.JADESecurityException;
import jade.security.util.SecurityData;
import jade.util.Logger;


/**
 * Implementation of the SignatureService, which role is to sign and verify
 * messages that have been encoded by the EncodingService
 *
 * @author Nicolas Lhuillier - Motorola Labs
 */
public class SignatureService extends BaseService {

	private AgentContainer myContainer;
	Filter in = new In();
	Filter out = new Out();

	private SecurityService ss;
	private MessagingService ms;


	public String getName() {
		return SignatureSlice.NAME;
	}

	public void init(AgentContainer ac, Profile p) throws ProfileException {
		super.init(ac, p);
		myContainer = ac;
	}

	public void boot(Profile p) throws ServiceException {
		try {
			// Retrieve the local SecurityService (used to perform basic security functions)
			ss = (SecurityService)myContainer.getServiceFinder().findService(SecuritySlice.NAME);
			// Retrieve the local MessagingService (used to notify failures to senders)
			ms = (MessagingService)myContainer.getServiceFinder().findService(MessagingSlice.NAME);
		}
		catch(ServiceException se) {
			throw se;
		}
		catch(Exception e) {
			throw new ServiceException("Unable to find local Security or Messaging services", e);
		}
	}
	
	public Filter getCommandFilter(boolean direction) {
		if (direction == Filter.INCOMING) {
			return in;
		}
		else {
			return out;
		}
	}


	/**
	 * Outgoing filter for signature service
	 */
	class Out extends Filter {

		public Out() {
			setPreferredPosition(30);
		}

		/**
		 * Sign the message contains in the command and update envelope info
		 */
		public boolean accept(VerticalCommand cmd) {
			String name = cmd.getName();

			// Only process if it is a SEND_MESSAGE CMD
			if (name.equals(MessagingSlice.SEND_MESSAGE)) {
				GenericMessage msg = null;
				AID sender = null;
				
				if (myLogger.isLoggable(Logger.FINEST)) {
					myLogger.log(Logger.FINEST, "Processing Incoming Command: "+cmd.getName());
				}

				Object[] params = cmd.getParams();
				try {
					msg = (GenericMessage)params[1];
					SecurityObject so;
					Envelope env = msg.getEnvelope();
					if (env != null) {
						if ((so=SecurityService.getSecurityObject(env,SecurityObject.SIGN)) != null) {
							if (myLogger.isLoggable(Logger.FINE)) {
								myLogger.log(Logger.FINE, "Signing message");
							}
							sender = (AID)params[0];
							Object obj = so.getEncoded();
							// Sign the message payload and update the security object with the signature unless already done.
							// Note in facts that if a message is sent to more than one receiver, when processing the message
							// for receivers number 2, 3... the signature has already been computed and stored in the SecurityData 
							// (Envelope cloning does not deep-clone envelope properties). As long as the payload does not change from 
							// receiver to receiver in facts the signature remains the same.
							if (obj instanceof SecurityData) {
								// SecurityData not yet prepared and encoded --> do the job
								SecurityData sd = (SecurityData)obj;
								Agent agt = myContainer.acquireLocalAgent(sender);
								SecurityHelper sh = (SecurityHelper)agt.getHelper(SecurityService.NAME);
								myContainer.releaseLocalAgent(sender);
								sd = sh.getAuthority().sign(sd.algorithm,msg.getPayload());
								so.setEncoded(sd);
								ACLMessage acl = msg.getACLMessage();
								if (acl!=null) so.setConversationId(acl.getConversationId());
								ss.encode(so);
							}
						}
					}
					else {
						// If envelope is null, ACLMessage can't be null
						env = msg.getACLMessage().getEnvelope();
						if ((env != null)&&((so=SecurityService.getSecurityObject(env,SecurityObject.SIGN)) != null)) {
							// This is a local message, the trick is that it is not signed
							// However we need to put the principal into the envelope
							sender = (AID)params[0];
							Agent agt = myContainer.acquireLocalAgent(sender);
							SecurityHelper sh = (SecurityHelper)agt.getHelper(SecurityService.NAME);
							((SecurityData)so.getEncoded()).key = sh.getPrincipal();
							myContainer.releaseLocalAgent(sender); 
						}
					}
				}
				catch(Exception e) {
					myLogger.log(Logger.WARNING, "Unexpected error processing message", e);
					try {
						// Reports the exception to the sender
						ss.reconstructACLMessage(msg);
						ms.notifyFailureToSender(msg, (AID) params[2], new InternalError(e.getMessage()));
					}
					catch(Exception ne) {
						cmd.setReturnValue(ne);
					}
					return false;
				}
			}
			return true;
		}

	} // End of Out class


	/**
	 * Incoming filter for signature service
	 */
	class In extends Filter {

		public In() {
			setPreferredPosition(30);
		}

		/**
		 * Verifies the signature of the received message
		 */
		public boolean accept(VerticalCommand cmd) {
			String name = cmd.getName();

			// Only process if it is a SEND_MESSAGE CMD
			if (name.equals(MessagingSlice.SEND_MESSAGE)) {
				GenericMessage msg = null;
				Object[] params = null;

				if (myLogger.isLoggable(Logger.FINEST)) {
					myLogger.log(Logger.FINEST, "Processing Incoming Command: "+cmd.getName());
				}

				try {
					params = cmd.getParams();
					msg = (GenericMessage)params[1];
					SecurityObject so;
					Envelope env = msg.getEnvelope();
					if ((env != null)&&((so=SecurityService.getSecurityObject(env,SecurityObject.SIGN)) != null)) {
						if (myLogger.isLoggable(Logger.FINE)) {
							myLogger.log(Logger.FINE, "Verifying message signature");
						}
						AID receiver = (AID)params[2];
						ss.decode(so);
						SecurityData sd = (SecurityData)so.getEncoded();
						Agent agt = myContainer.acquireLocalAgent(receiver);
						SecurityHelper sh = (SecurityHelper)agt.getHelper(SecurityService.NAME);
						myContainer.releaseLocalAgent(receiver);
						if (! sh.getAuthority().verifySignature(sd, msg.getPayload())) {
							throw new JADESecurityException("Invalid signature");
						}
					}
				}
				catch(Exception e) {
					myLogger.log(Logger.WARNING, "Unexpected error processing message", e);
					try {
						// Reports the exception to the sender
						ss.reconstructACLMessage(msg);
						ms.notifyFailureToSender(msg, (AID)params[2], new InternalError(e.getMessage()));
					}
					catch(Exception ne) {
						cmd.setReturnValue(ne);
					}
					return false;
				}
			}
			return true;
		}

	} // End of In class
}
