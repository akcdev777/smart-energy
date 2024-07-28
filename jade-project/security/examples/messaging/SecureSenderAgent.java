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
package messaging;

import jade.core.*;
import jade.core.behaviours.*;
import jade.core.security.*;
import jade.security.JADEPrincipal;
import jade.lang.acl.*;
import jade.domain.FIPAService;
import jade.util.leap.Iterator;

/**
   This is an agent that sends a signed message to a given receiver.
   The message content, the receiver local name and the are taken as command 
   line parameters.

   @author Giovanni Caire - TILAB
 */
public class SecureSenderAgent extends Agent {

	private SecurityHelper mySecurityHelper = null;
	private SecureSenderGui myGui = null;

	protected void setup() {
		try {
			// Get the SecurityHelper
			mySecurityHelper = (SecurityHelper) getHelper("jade.core.security.Security");

			myGui = new SecureSenderGui(this);
			myGui.showCorrect();
		}
		catch (ServiceException se) {
			se.printStackTrace();
			doDelete();
		}
	}

	protected void takeDown() {
		if (myGui != null) {
			myGui.dispose();
		}
	}

	/**
     This method is called by the GUI when the user clicks on the 
     OK button of the ACLGUI that appears when the Send button is 
     pressed.
	 */
	public void sendMessage(ACLMessage msg, boolean signed, boolean encrypted) {
		if (signed) {
			// The message must be signed
			mySecurityHelper.setUseSignature(msg);
		}

		if (encrypted) {
			// The message must be encrypted --> be sure that all receiver
			// principals are trusted. Basically this means retrieving the 
			// public key of the receivers that is required to encrypt the message.
			// For agents that live in the same platform this step is not 
			// required since the platform can retrieve the necessary 
			// information automatically.
			Iterator it = msg.getAllReceiver();
			while (it.hasNext()) {
				AID receiver = (AID) it.next();
				if (mySecurityHelper.getTrustedPrincipal(receiver.getName()) == null) {
					try {
						System.out.println(getName()+": Retrieving principal for agent "+receiver.getName()+"...");
						JADEPrincipal principal = retrievePrincipal(receiver);
						System.out.println(getName()+": Principal for agent "+receiver.getName()+" retrieved: "+principal);
						mySecurityHelper.addTrustedPrincipal(principal);
					}
					catch (Exception e) {
						System.out.println(getName()+": Error retrieving the principal for agent "+receiver.getName());
						e.printStackTrace();
					}
				}
			}

			mySecurityHelper.setUseEncryption(msg);
		}

		System.out.println(getName()+": Sending message (sign "+signed+", encrypt "+encrypted+")");
		send(msg);
	}

	private JADEPrincipal retrievePrincipal(AID id) throws Exception {
		// Request the principal to the agent
		ACLMessage request = new ACLMessage(ACLMessage.REQUEST);
		request.addReceiver(id);
		request.setContent(SecureReceiverAgent.GET_PRINCIPAL);
		mySecurityHelper.setUseSignature(request);
		ACLMessage reply = FIPAService.doFipaRequestClient(this, request, 5000);
		if (reply != null) {
			return mySecurityHelper.getPrincipal(reply);
		}
		else {
			throw new Exception("No reply received to get-principal request for agent "+id.getName());
		}
	}
}

