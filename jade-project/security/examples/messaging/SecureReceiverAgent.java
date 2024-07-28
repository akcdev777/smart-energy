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
import jade.lang.acl.*;

/**
   This is an agent that waits for messages and prints those that 
   are signed while discards those that are not.

   @author Giovanni Caire - TILAB
 */
public class SecureReceiverAgent extends Agent {
	public static final String GET_PRINCIPAL = "get-principal";

	private SecurityHelper mySecurityHelper = null;

	protected void setup() {
		try {
			// Get the SecurityHelper
			mySecurityHelper = (SecurityHelper) getHelper("jade.core.security.Security");

			// Add the behaviour listening for incoming messages
			addBehaviour(new CyclicBehaviour(this) {
				public void action() {
					ACLMessage msg = myAgent.receive();
					if (msg != null) {
						if (mySecurityHelper.getUseSignature(msg)) {
							if (GET_PRINCIPAL.equals(msg.getContent())) {
								System.out.println(myAgent.getName()+": Principal request received from "+msg.getSender().getName()+". Replying...");
								ACLMessage reply = msg.createReply();
								reply.setPerformative(ACLMessage.INFORM);
								mySecurityHelper.setUseSignature(reply);
								myAgent.send(reply);
							}
							else { 
								if (mySecurityHelper.getUseEncryption(msg)) {
									System.out.println(myAgent.getName()+": Signed and encrypted message received:");
								}
								else { 
									System.out.println(myAgent.getName()+": Signed message received:");
								}
								System.out.println(msg);
							}
						} 
						else {
							System.out.println(myAgent.getName()+": Received NON signed message from "+msg.getSender().getName());
							System.out.println(myAgent.getName()+": Discard it");
						}
					}
					else {
						block();
					}
				}
			} );
		}
		catch (ServiceException se) {
			se.printStackTrace();
			doDelete();
		}

		System.out.println(getName()+": Ready to accept secure messages...");
	}
}

