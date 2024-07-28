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

import jade.core.Agent;
import jade.core.AID;
import jade.core.security.*;
import jade.security.util.*;
import jade.core.security.authentication.*;
import jade.security.*;
import jade.security.impl.SDSINameImpl;
import jade.security.impl.JADEPrincipalImpl;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;

/**
 * This class is a generic message sender for the security tests.
 *
 * The actual action performed by the agent is defined by the parameters 
 * passed as bootstrap arguments:
 * - arg[0]: shall message be signed (true/false)
 * - arg[1]: shall message be encrypted (true/false)
 * - arg[2]: 
 *
 * @author Nicolas Lhuillier - Motorola Labs
 */
public class CredentialsSender extends Agent {
  
  
  private boolean encrypt = false;
  private byte[] destKey;
  private String destAlgo;
  private AID dest;
  private SecurityHelper se;

  public void setup(){
    ACLMessage msg = null;
    try { 
      // retrieve agents arguments
      Object [] args = getArguments();
      
      //DEBUG
      /*
        for(int i=0;i<args.length;i++) { 
        System.out.println("args["+i+"] = ***"+args[i]+"***");
        }
      */

      if (args.length == 2) {
        encrypt = false;
      }
      else if (args.length == 4) {
        encrypt = true;
        String s = ((String)args[2]).replace('*', '=');
        destKey = Base64.decodeBase64((byte[]) s.getBytes());

        destAlgo = (String)args[3];
      
      }
      else {
        throw new Exception("Bad argument number: "+args.length); 
      }
      
      dest = new AID((String)args[0],AID.ISGUID);
      if (isSet((String)args[1])) {
        dest.addAddresses((String)args[1]);
      } 
      
      // DEBUG
      System.out.println("Credentials sender agent launched");
      se = (SecurityHelper)getHelper(SecurityService.NAME);
      // prepare message to be sent to the security agent
      msg = new ACLMessage(ACLMessage.INFORM); 
      se.addCredentials(msg,prepareCredentials());
        
      if (encrypt) {
        JADEPrincipal jp = new JADEPrincipalImpl(dest.getName(),new SDSINameImpl(destKey,destAlgo,null));
        se.addTrustedPrincipal(jp);
        se.setUseEncryption(msg);
      }
    }
    catch (Exception e) {
      msg = new ACLMessage(ACLMessage.FAILURE);
      msg.setContent(e.getMessage());
      // DEBUG
      e.printStackTrace();
		}
    finally {
      msg.addReceiver(dest);
      send(msg);
      System.out.println("Message sent");
      // DEBUG
      System.out.println(msg);
      System.out.println(msg.getEnvelope());
    }
    // Check if there is a failure message and forwards it to the tester agent
    //System.out.println("Waiting for a failure just in case");
    msg = blockingReceive(MessageTemplate.MatchPerformative(ACLMessage.FAILURE));
    //System.out.println("Failure received");
    //System.out.println(msg);
    msg.setEnvelope(null);
    msg.clearAllReceiver();
    msg.addReceiver(dest);
    send(msg);
    //System.out.println("Failure sent");
    //System.out.println(msg);
  }
  
  private boolean isSet(String p) {
    //return ((p != null)&&(! "null".equals(p)));
    return (! "null".equals(p));
  }

  /*
   * This method creates a CredentialsSet containing:
   * - 1 UserPassCredential
   * - 1 OwnershipCertificate
   * - 1 GroupCertificate
   * - 1 NameCertificate
   */ 
  private Credentials prepareCredentials() {
    UserPassCredential upc = new UserPassCredential(CredentialsTest.USERNAME,CredentialsTest.PASSWORD);
    JADEPrincipal me = se.getPrincipal();
    // Create a self signed certificate
    OwnershipCertificate oc = new OwnershipCertificate(me,me);
    try {
      oc.setSignature(se.getAuthority().sign(se.getSignatureAlgorithm(),oc.getEncoded()));
    }
    catch(Exception ex) {
      System.out.println("Error signing certificate: "+ex);
    }
    Credentials res = CredentialsEngine.add(upc,oc);
    GroupCertificate gc = new GroupCertificate(me);
    res = CredentialsEngine.add(res,gc);
    NameCertificate nc = new NameCertificate(me);
    res = CredentialsEngine.add(res,nc);
    return res;
  }


}
