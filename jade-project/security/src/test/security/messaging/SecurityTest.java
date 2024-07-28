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

package test.security.messaging;

import jade.core.*;
import jade.core.behaviours.*;
import jade.lang.acl.ACLMessage;
import jade.core.security.SecurityHelper;
import jade.security.*;

import test.common.*;
import test.security.*;

import org.apache.commons.codec.binary.Base64;

/**
 * This class is a generic security test
 *
 * @author Jerome Picault - Motorola Labs
 * @author Nicolas Lhuillier - Motorola Labs
 */
public class SecurityTest extends Test {
	
	public static final String CONTENT = "Test content";
	private static final String REMOTE_NAME = "RemotePlaform";
  private static final String REMOTE_PORT = "2000";
	private static final String REMOTE_AGENT = "MessageSender";
  private static final String REMOTE_CLASS = "test.security.messaging.MessageSender";

  public static final String SIGN_KEY = "sign";
  public static final String ENCRYPT_KEY = "encrypt";
  public static final String PASS_KEY = "pass";
  public static final String SIGN_ALGO_KEY = "sign-algo";
  public static final String SYM_ALGO_KEY = "sym-algo";
  public static final String PUBLIC_KEY_KEY = "public-key";
  public static final String SYM_ALGO_SIZE = "sym-size";
  public static final String CONFIG_KEY = "config";
  
  // Constants for configuration
  public static final String INTER = "platform";
  public static final String EXTRA = "remote";
  private static final String NO_AUTH = "-jade.security.authentication.loginmodule SingleUser";

	private JadeController senderHost;
	private SecurityHelper sh;
  private AID senderAID = null;
  
  private boolean sign = false;
  private boolean encrypt = false;
  private boolean shouldPass = true;
	private boolean publicKey = true;
  
  public Behaviour load(Agent a) throws TestException {
    try {
      String tmp;
      if ((tmp=getTestArgument(SIGN_KEY)) != null) {
        sign = new Boolean(tmp).booleanValue(); 
      }
      if ((tmp=getTestArgument(ENCRYPT_KEY)) != null) {
        encrypt = new Boolean(tmp).booleanValue(); 
      }
      if ((tmp=getTestArgument(PASS_KEY)) != null) {
        shouldPass = new Boolean(tmp).booleanValue(); 
      }
      if ((tmp=getTestArgument(PUBLIC_KEY_KEY)) != null) {
        publicKey = new Boolean(tmp).booleanValue(); 
      }

      sh = (SecurityHelper)a.getHelper(jade.core.security.SecurityService.NAME);

      SequentialBehaviour b1 = new SequentialBehaviour(a);
      // Step 1: Starts the remote sender
      b1.addSubBehaviour(new OneShotBehaviour(a) {
          public void action() {
            String[] agtParams = new String[9];
            agtParams[0] = String.valueOf(sign);
            agtParams[1] = String.valueOf(encrypt);
            agtParams[2] = getTestArgument(SIGN_ALGO_KEY);
            agtParams[3] = getTestArgument(SYM_ALGO_KEY);
            agtParams[4] = getTestArgument(SYM_ALGO_SIZE);

            if ((encrypt)&&(publicKey)) {
              SDSIName tmp = sh.getPrincipal().getSDSIName();
              String encodedKey = new String(Base64.encodeBase64(tmp.getEncoded()));
              encodedKey = encodedKey.replace('=', '*');
              agtParams[5] = encodedKey;
              agtParams[6] = tmp.getAlgorithm();
            }
            agtParams[7] = myAgent.getName();
          
            // Avoid null parameters that crash with the ontology
            for (int i=0; i<agtParams.length; i++) {
              if (agtParams[i] == null) {
                agtParams[i] = "null";
              }
            }

            try {
              String config = getTestArgument(CONFIG_KEY);
              if (EXTRA.equalsIgnoreCase(config)) {
                // Sets the address in the parameters
                agtParams[8] = (String)myAgent.getAID().getAllAddresses().next();

                // Starts the sender on a remote platform
                String params = "-name "+REMOTE_NAME+" -port "+REMOTE_PORT;
                if (! "".equals(RemoteSecurityTesterAgent.MTP)) {
                  params += " -mtp "+RemoteSecurityTesterAgent.MTP;
                }
                String clp = null;
                if (! "".equals(RemoteSecurityTesterAgent.CLASSPATH)) {
                  clp = "+"+RemoteSecurityTesterAgent.CLASSPATH;
                }
                // Plug the security services
                params += " -services "+SecurityTestSuite.SECURITY_SERVICES;
                params += " "+NO_AUTH;
                params += " "+REMOTE_AGENT+":"+REMOTE_CLASS+toLine(agtParams);
                senderHost = TestUtility.launchJadeInstance(REMOTE_NAME, clp, params, null);
              
              }
              else if(INTER.equalsIgnoreCase(config)) {
                // Starts the sender on a remote container
                String params = "-container";
                params += " -dump";
                params += " -services "+SecurityTestSuite.SECURITY_SERVICES;
                params += " "+NO_AUTH;
                params += " -jade_core_management_AgentManagementServices_verbosity 4";
                params += "  "+REMOTE_AGENT+":"+REMOTE_CLASS+toLine(agtParams);
                senderHost = TestUtility.launchJadeInstance(REMOTE_NAME,null, params, null);
              }
              else {
                // Starts the sender on the local container
                senderAID = TestUtility.createAgent(myAgent, REMOTE_AGENT, REMOTE_CLASS, agtParams);
              }
            }
            catch(Exception te) {
              failed("Error creating remote agent: "+te.getMessage());
              // DEBUG
              te.printStackTrace();
            }
          }
        });

      // Step 2: Waits for the message and checks it
      b1.addSubBehaviour(new SimpleBehaviour(a) {

          private boolean done = false;

          public void action() {
            ACLMessage msg = myAgent.receive();
            if (msg == null) {
              block();
            }
            else {
              try {
                if (msg.getPerformative() == ACLMessage.INFORM) {
                  // If the message gets there it means that everything went well so far
                  SecurityHelper sh = (SecurityHelper)myAgent.getHelper(jade.core.security.SecurityService.NAME);
                  if ( (shouldPass) &&
                       (! (sign^sh.getUseSignature(msg))) && 
                       (! (encrypt^sh.getUseEncryption(msg))) &&
                       (CONTENT.equals(msg.getContent())) ) {
                    passed("Everything happened as expected");
                  }
                  else {
                    failed("An error was expected to occur");
                  }
                }
                else {
                  if (shouldPass) {
                    failed("Unexpectedly received a failure:\n"+msg.getContent());
                  }
                  else {
                    passed("Received a failure as expected:\n"+msg.getContent());
                  }
                }
                done = true;
              }
              catch(ServiceException se) {
                // So far this should not happen
                failed("Unexpected: "+se.getMessage());
              }   
            }
          }
        
          public boolean done() {
            return done;
          }
        });
    
      // If we don't receive any message in 30 sec --> TEST_FAILED
      Behaviour b2 = new WakerBehaviour(a, 30000) {
          protected void handleElapsedTimeout() {
            failed("Message timeout expired");
          }
        };
    
      ParallelBehaviour b = new ParallelBehaviour(a, ParallelBehaviour.WHEN_ANY); 
      b.addSubBehaviour(b1);
      b.addSubBehaviour(b2);
    
      return b;
    }
    catch (Exception e) {
      throw new TestException(e.getMessage());
    } 
  }
  
  public void clean(Agent a) {
  	// Kill the remote container
  	if (senderHost != null) {
			senderHost.kill();
  	}
    else if(senderAID != null) {
      try {
        // Just kill the remote agent
        TestUtility.killAgent(a,senderAID);
      }
      catch(TestException te) {
        System.err.println(te);
      }
    }
  }  	
 
  private String toLine(String[] s) {
    String result = "(";
    for (int i=0;i<s.length;i++) {
      result += s[i];
      if (i<s.length-1) result +=" ";
    }
    result += ")";
    return result;
  }

}
