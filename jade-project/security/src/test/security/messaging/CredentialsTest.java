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
import jade.core.security.*;
import jade.security.util.*;
import jade.core.security.authentication.*;

import jade.security.*;

import test.common.*;
import test.security.*;

import org.apache.commons.codec.binary.Base64;

import java.util.Enumeration;

/**
 * This class tests usage of credentials in ACLMessage 
 *
 * @author Nicolas Lhuillier - Motorola Labs
 */
public class CredentialsTest extends Test {
	
	public static final String USERNAME = "MyUserName";
  public static final byte[] PASSWORD = "MyPassword".getBytes();
  public static final String PERMISSION = "";
	
  private static final String REMOTE_NAME = "RemotePlaform";
  private static final String REMOTE_PORT = "2000";
	private static final String REMOTE_AGENT = "CredsSender";
  private static final String REMOTE_CLASS = "test.security.messaging.CredentialsSender";

  public static final String ENCRYPT_KEY = "encrypt";
  public static final String CONFIG_KEY = "config";
  
  // Constants for configuration
  public static final String INTER = "platform";
  public static final String EXTRA = "remote";
  private static final String NO_AUTH = "-jade.security.authentication.loginmodule SingleUser";

	private JadeController senderHost;
	private SecurityHelper sh;
  private AID senderAID = null;
  
  private boolean encrypt = false;
  
  public Behaviour load(Agent a) throws TestException {
    try {
      String tmp;
      if ((tmp=getTestArgument(ENCRYPT_KEY)) != null) {
        encrypt = new Boolean(tmp).booleanValue(); 
      }

      sh = (SecurityHelper)a.getHelper(jade.core.security.SecurityService.NAME);

      SequentialBehaviour b1 = new SequentialBehaviour(a);
      // Step 1: Starts the remote sender
      b1.addSubBehaviour(new OneShotBehaviour(a) {
          public void action() {
            
            String[] agtParams;
            if (encrypt) {
              agtParams = new String[4];
              SDSIName tmp = sh.getPrincipal().getSDSIName();
              String encodedKey = new String(Base64.encodeBase64(tmp.getEncoded()));
              encodedKey = encodedKey.replace('=', '*');
              agtParams[2] = encodedKey;
              agtParams[3] = tmp.getAlgorithm();
            }
            else {
              agtParams = new String[2];
            }
            agtParams[0] = myAgent.getName();
          
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
                agtParams[1] = (String)myAgent.getAID().getAllAddresses().next();

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
                params += " -services "+SecurityTestSuite.SECURITY_SERVICES;
                params += " "+NO_AUTH;
                params += " "+REMOTE_AGENT+":"+REMOTE_CLASS+toLine(agtParams);
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
                  System.out.println("msg received:\n"+msg);
                  if (checkCredentials(sh.getCredentials(msg))) {
                    passed("Everything happened as expected");
                  }
                  else {
                    failed("Credentials not properly transported");
                  }
                }
                else {
                  failed("Unexpectedly received a failure:\n"+msg.getContent());
                }
                done = true;
              }
              catch(JADESecurityException jse) {
                failed("SecurityException: "+jse.getMessage());
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
  
  private boolean checkCredentials(Credentials creds) throws JADESecurityException {
    try {
      int i = 0;
      for(Enumeration e = creds.elements();e.hasMoreElements();i++) {      
        Credentials tmp = (Credentials)e.nextElement();
        System.out.println("Processing a "+tmp.getClass().getName());
        if (tmp instanceof UserPassCredential) {
          UserPassCredential upc = (UserPassCredential) tmp;
          if ( (! USERNAME.equals(upc.getUsername())) && 
               (! PASSWORD.equals(upc.getPassword())) ) {
            System.out.println("Incorrect username/password in UserPassCredential");
            break;
          }
        }
        else if (tmp instanceof GroupCertificate) {
          GroupCertificate gc = (GroupCertificate) tmp;
          if (gc.getOwner() == null) {
            System.out.println("Incorrect group principal in GroupCertificate");
            break;
          }
        }
        if (tmp instanceof OwnershipCertificate) {
          OwnershipCertificate oc = (OwnershipCertificate) tmp;
          if (! sh.getAuthority().verifySignature(oc.getSignature(),oc.getEncoded())) {
            System.out.println("Incorrect signature in OwnershipCertificate");
            break;
          }
        
        }
      }
      System.out.println("There was "+i+" good credential(s) in message instead of 4");
      return (i == 4);
    }
    catch(Exception e) {
      return false;
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
      result += s[i] + " ";
    }
    result += ")";
    return result;
  }

}
