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


package test.security.permission;

import jade.core.Agent;
import jade.core.behaviours.Behaviour;
import jade.core.behaviours.OneShotBehaviour;
import jade.core.behaviours.SequentialBehaviour;
import jade.core.security.SecurityHelper;
import test.common.JadeController;
import test.common.Logger;
import test.common.Test;
import test.common.TestException;
import test.common.TestUtility;
import java.security.ProtectionDomain;
import java.security.PermissionCollection;
import java.security.Permission;
import java.security.Policy;
import java.util.Enumeration;
import jade.lang.acl.ACLMessage;
import jade.core.AID;
import test.content.Responder;



/**
 * @author Giosue.Vitaglione@telecomitalia.it
 * @version $Date: 2004-07-14 15:16:06 +0200 (mer, 14 lug 2004) $ $Revision: 416 $
 */

public class AgentCreateTest1
    extends PermissionTest {

  public void action() {

    boolean mainStarted = false;

    // START MAIN CONTAINER  AS ALICE
    try {
    newPlatform = TestUtility.launchJadeInstance(
        NEW_PLATFORM_NAME, null,
         " -conf " + getTestArgument(MAIN_CONFIG_FILE_KEY) 
        +" -owner bob:bob"
        +" -java.security.policy " + getTestArgument(MAIN_POLICY_FILE_KEY) 
        , null);
    } catch (Exception te) {
      //te.printStackTrace();
      mainStarted = false;
      failed("failed starting the MAIN container");
    }

    boolean cont1Started = false;

    // START CONT-1 WITH THE AGENT  AS BOB
    try {
      cont1 = TestUtility.launchJadeInstance(
          NEW_PLATFORM_NAME, null,
           " -conf " + getTestArgument(CONT1_CONFIG_FILE_KEY) 
          +" -continer"
          +" -owner bob:bob"
          +" -java.security.policy " + getTestArgument(CONT1_POLICY_FILE_KEY) 
          +" responder:test.content.Responder"
          , new String[]{"http"} );

      if (cont1 != null) {
        cont1Started = true;
      } else {
        cont1Started = false;
      }
    } catch (Exception te) {
      //te.printStackTrace();
      cont1Started = false;
    }

    // prepare a message
    String platformName = NEW_PLATFORM_NAME;
    String address = (String) cont1.getAddresses().get(0);
    AID responderAID = new AID("responder@"+platformName);
    responderAID.addAddresses(address);
    int PERFORMATIVE1 = ACLMessage.REQUEST;
    ACLMessage msg2send = new ACLMessage( PERFORMATIVE1 );
    msg2send.setConversationId( Responder.TEST_CONVERSATION );
    msg2send.setReplyWith( Responder.TEST_RESPONSE_ID);
    msg2send.setContent("ciao");

    getTesterAgent().send( msg2send );

    boolean agentStarted = false;

    // wait for a message from the created agent
    int AGENT_CREATE_TIMEOUT=10000;
    ACLMessage msgFromNewAgent = getTesterAgent().blockingReceive(AGENT_CREATE_TIMEOUT);
    if (    (msgFromNewAgent==null) 
         || (!msgFromNewAgent.getContent().equals("ciao"))
         || (msgFromNewAgent.getPerformative()!=PERFORMATIVE1)
        ) {
      // agent did not send the message, probably it did not start correctly
      agentStarted=false;
    }


    boolean shouldPass = "true".equals(getTestArgument(SHOULD_SUCCEED_KEY));

    StringBuffer msg = new StringBuffer("Agent");
    if (agentStarted) {
      msg.append("started correctly ");
    } else {
      msg.append("did not started correctly ");
    }

    if (shouldPass == agentStarted) {
      passed("OK, "+msg.toString());
    } else {
      failed(" :-(  "+msg.toString());
    }

  } // end action

} // end class