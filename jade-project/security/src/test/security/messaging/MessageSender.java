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
import jade.core.security.SecurityHelper;
import jade.security.JADEPrincipal;
import jade.security.impl.SDSINameImpl;
import jade.security.impl.JADEPrincipalImpl;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import org.apache.commons.codec.binary.Base64;

/**
 * This class is a generic message sender for the security tests.
 *
 * The actual action performed by the agent is defined by the parameters 
 * passed as bootstrap arguments:
 * - arg[0]: shall message be signed (true/false)
 * - arg[1]: shall message be encrypted (true/false)
 * - arg[2]: signature algorithm (null means default)
 * - arg[3]: symmetric encryption algorithm (null means default)
 * - arg[4]: receiver's public key (for encryption)
 * - arg[5]: receiver's public key algorithm
 * - arg[6]: receiver's name (GUID)
 * - arg[7]: receiver's address
 *
 * @author Jerome Picault - Motorola Labs
 * @author Nicolas Lhuillier - Motorola Labs
 */
public class MessageSender extends Agent {
  
  private boolean sign = false;
  private boolean encrypt = false;
  private String signAlgo;
  private String symAlgo;
  private int keySize;
  private byte[] destKey;
  private String destAlgo;
  private AID dest;
  
  public void setup(){
    System.out.println("MessageSender setup()");

    ACLMessage msg = null;
    try { 
      // retrieve agents arguments
      Object [] args = getArguments();
      
      if (args.length != 9) { 
        throw new Exception("Bad argument number: "+args.length+" instead of 9");
      }
      
      //DEBUG
      //-*
        for(int i=0;i<args.length;i++) { 
        System.out.println("args["+i+"] = ***"+args[i]+"***");
        }
      //*/
      
      // parse arguments
      dest = new AID((String)args[7],AID.ISGUID);
      if (isSet((String)args[8])) {
        dest.addAddresses((String)args[8]);
      }
      sign = (new Boolean((String)args[0])).booleanValue();
      encrypt = (new Boolean((String)args[1])).booleanValue();
      signAlgo = (String)args[2];
      symAlgo = (String)args[3];
      if (isSet((String)args[4])) {
        keySize = Integer.parseInt((String)args[4]);
      }
      if (isSet((String)args[5])) {
        destKey = Base64.decodeBase64(((String)args[5]).replace('*', '=').getBytes());
      }
      destAlgo = (String)args[6];
      
      
      // DEBUG
      System.out.println("Message sender agent launched");
      
      // prepare message to be sent to the security agent
      msg = new ACLMessage(ACLMessage.INFORM); 
      msg.setContent(SecurityTest.CONTENT);
      
      SecurityHelper se = (SecurityHelper)getHelper(jade.core.security.SecurityService.NAME);
      
      if (sign) {
        if (isSet(signAlgo)) {
          se.setSignatureAlgorithm(signAlgo);
        }
        se.setUseSignature(msg);
      }
      if (encrypt) {
        if (isSet(symAlgo)) {
          se.setSymmetricAlgorithm(symAlgo);
        }
        if (keySize != 0) {
          se.setKeySize(keySize);
        }
        if (isSet(destAlgo)) {
          JADEPrincipal jp = new JADEPrincipalImpl(dest.getName(),new SDSINameImpl(destKey,destAlgo,null));
          se.addTrustedPrincipal(jp);
        }
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
      //System.out.println("Message sent");
      // DEBUG
      //System.out.println(msg);
      //System.out.println(msg.getEnvelope());
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

}
