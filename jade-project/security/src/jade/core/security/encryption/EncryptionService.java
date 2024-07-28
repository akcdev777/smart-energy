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

package jade.core.security.encryption;

//#MIDP_EXCLUDE_FILE

import jade.core.AID;
import jade.core.Agent;
import jade.core.AgentContainer;
import jade.core.BaseService;
import jade.core.Filter;
import jade.core.Profile;
import jade.core.ProfileException;
import jade.core.ServiceException;
import jade.core.VerticalCommand;
import jade.core.messaging.GenericMessage;
import jade.core.messaging.MessagingService;
import jade.core.messaging.MessagingSlice;
import jade.core.security.SecurityHelper;
import jade.core.security.SecurityService;
import jade.core.security.SecuritySlice;
import jade.domain.FIPAAgentManagement.Envelope;
import jade.domain.FIPAAgentManagement.InternalError;
import jade.domain.FIPAAgentManagement.Property;
import jade.domain.FIPAAgentManagement.SecurityObject;
import jade.lang.acl.ACLMessage;
import jade.security.JADEPrincipal;
import jade.util.Logger;


/**
 * Implementation of the EncryptionService,
 * which role is to encrypt or decrupt messages before they are delivered to agents
 * Incoming messages: must have been previously verified by the SignatureService
 * and need then to be decoded by the EncodingService
 * Outgoing messages: must have been encoded by the EncodingService
 * and need then to be signed by the SignatureService
 *
 * @author Nicolas Lhuillier - Motorola Labs
 * @author jerome Picault - Motorola Labs
 */
public class EncryptionService extends BaseService {
	private AgentContainer myContainer;
	private Filter in = new In();
	private Filter out = new Out();
	
	private SecurityService ss;
	private MessagingService ms;
	
	public String getName() {
		return EncryptionSlice.NAME;
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
	 * Outgoing filter for encryption service
	 */
	class Out extends Filter {

		public Out(){
			// sets the relative position of the filter in the filter chain.
			setPreferredPosition(50);
		}

		/**
		 * Encrypt the message contained in the command and update envelope info
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
					Envelope env = msg.getEnvelope();
					if (env != null) {
						Property securityObjectsProp = SecurityService.getSecurityObjectsProperty(env);
						if (securityObjectsProp != null) {
							// Security information present
							SecurityObject[] sos = (SecurityObject[]) securityObjectsProp.getValue();
							SecurityObject so = SecurityService.getSecurityObject(sos, SecurityObject.ENCRYPT);
							if (so != null) {
								// Encryption SecurityObject present
								if (myLogger.isLoggable(Logger.FINE)) {
									myLogger.log(Logger.FINE, "Encrypting message");
								}
								sender = (AID)params[0];
								Agent agt = myContainer.acquireLocalAgent(sender);
								SecurityHelper sh = (SecurityHelper)agt.getHelper(SecurityService.NAME);
								myContainer.releaseLocalAgent(sender);
		
								// Encrypts the message payload and update the security object.
								// NOTE: Since the message may have more than one receiver, for receivers 2, 3... we must 
								// clone the encryption SecurityObject and therefore the whole SecurityObject-s array (Envelope 
								// cloning does not deep-clone envelope properties). This is because the
								// SecurityData included in the encryption SecurityObject is different for each receiver
								// as it holds a new symmetric key encrypted with the receiver's public key.
								boolean needClone = so.getEncoded() instanceof byte[]; // If at this stage SecurityData is already encoded, we are processing the message for receiver 2, 3... --> Need clone
								SecurityObject actualSo = so;
								if (needClone) {
									actualSo = (SecurityObject) so.clone();
									ss.decode(actualSo);
								}
								JADEPrincipal receiverPrincipal = sh.getPrincipal(((AID)params[2]).getName());
								byte[] enc = sh.getAuthority().encrypt(actualSo, msg.getPayload(), receiverPrincipal);
								// Obfuscate some fields in the ACLMessage
								ACLMessage acl = msg.getACLMessage();
								if (acl != null) { 
									acl.setContent(null);
									actualSo.setConversationId(acl.getConversationId());
								}
								ss.encode(actualSo);
								if (needClone) {
									SecurityObject[] clonedSos = new SecurityObject[sos.length];
									for (int i = 0; i < sos.length; ++i) {
										if (sos[i] == so) {
											// Replace the original SecurityObject with the modified one 
											clonedSos[i] = actualSo;
										}
										else {
											clonedSos[i] = sos[i];
										}
									}
									securityObjectsProp.setValue(clonedSos);
								}
								// update the Generic Message in the command
								msg.update(acl, env, enc);
								
							}
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
	 * Incoming filter for encryption service
	 */
	class In extends Filter {

		public In(){
			// sets the relative position of the filter in the filter chain.
			setPreferredPosition(10);
		}

		/**
		 * Verifies the signature of the received message
		 */
		public boolean accept(VerticalCommand cmd) {
			String name = cmd.getName();

			// Only process if it is a SEND_MESSAGE CMD
			if (name.equals(MessagingSlice.SEND_MESSAGE)) {
				GenericMessage msg = null;
				Object[] params = cmd.getParams();

				if (myLogger.isLoggable(Logger.FINEST)) {
					myLogger.log(Logger.FINEST, "Processing Incoming Command: "+cmd.getName());
				}

				try {
					msg = (GenericMessage)params[1];
					SecurityObject so;
					Envelope env = msg.getEnvelope();

					if ((env != null)&&((so=SecurityService.getSecurityObject(env,SecurityObject.ENCRYPT)) != null)) {
						if (myLogger.isLoggable(Logger.FINE)) {
							myLogger.log(Logger.FINE, "Decrypting message");
						}
						AID receiver = (AID)params[2];
						Agent agt = myContainer.acquireLocalAgent(receiver);
						SecurityHelper sh = (SecurityHelper)agt.getHelper(SecurityService.NAME);
						myContainer.releaseLocalAgent(receiver);

						// decrypt payload
						ss.decode(so);
						byte[] dec = sh.getAuthority().decrypt(so,msg.getPayload());
						// update the command
						msg.update(msg.getACLMessage(), env, dec);
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
