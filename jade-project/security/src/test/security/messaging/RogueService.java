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

//#MIDP_EXCLUDE_FILE

import jade.core.*;
import jade.core.security.*;
import jade.security.util.*;
import jade.core.messaging.*;
import jade.lang.acl.*;
import jade.domain.FIPAAgentManagement.*;
import jade.security.impl.*;
import jade.security.*;

import java.security.KeyPairGenerator;
import java.util.Random;

/**
 * Implementation of the SignatureService, which role is to sign and verify
 * messages that have been encoded by the EncodingService
 *
 * @author Nicolas Lhuillier - Motorola Labs
 *
 */
public class RogueService extends BaseService {

  // the filter performing the real authorization check
  private RogueFilter filter;
  
  public static final String ACTION_KEY = "test_security_messaging_RogueService_action";
  
  // Constants for ROGUE actions
  public static final String SIG_KEY = "signature-key";
  public static final String SIG_KE2 = "signature-key-wrong";
  public static final String SIG_KAL = "signature-key-algorithm";
  public static final String SIG_KA2 = "signature-key-algorithm-wrong";
  public static final String SIG_VAL = "signature-value";
  public static final String SIG_ALG = "signature-algorithm";
  public static final String SIG_AL2 = "signature-algorithm-unknown";
  public static final String SIG_PAY = "signature-payload";
  
  public static final String ENC_KEY = "encryption-key";
  public static final String ENC_KE2 = "encryption-key-wrong";
  public static final String ENC_ALG = "encryption-algorithm";
  public static final String ENC_AL2 = "encryption-algorithm-unknown";
  public static final String ENC_PAY = "encryption-payload";

  public String getName() {
    return RogueSlice.NAME;
  }

  public void init(AgentContainer ac, Profile p) throws ProfileException {
    super.init(ac, p);

    String action = null;
    // set verbosity level for logging
    try {
      action = p.getParameter(ACTION_KEY,null);
    }
    catch (Exception e) {
      // Ignore and keep default (0)
    }
    
    // create and initialize the filter of this service
    filter = new RogueFilter(action);    
  }
  
  public Filter getCommandFilter(boolean direction) {
    
    if (direction == Filter.INCOMING) {
      return null;
    }
    else {
      return filter;
    }
    
  }
  
  public static class RogueFilter extends Filter {
    
    private String action;
    private Random rnd; 
    private SOCodec soCodec;
    private ACLCodec aclCodec;
    
    public RogueFilter(String a) {
      action = a;
      soCodec = new BasicSOCodec();
      aclCodec = new LEAPACLCodec();
      rnd = new Random(System.currentTimeMillis());    
      setPreferredPosition(90);
    }
    
    /**
     * Modify security information in the envelope
     */
    public boolean accept(VerticalCommand cmd) {
      String name = cmd.getName();
      
      // Only process if it is a SEND_MESSAGE CMD
      if (name.equals(MessagingSlice.SEND_MESSAGE)) {
        GenericMessage msg = null;
        //System.out.println("\n[RogueFilter] Hacking a \"SEND_MESSAGE\" command");
           
        try {
          // params[0] = sender (AID)
          // params[1] = generic message (acl + envelope + payload)
          // params[2] = receiver (AID)
          Object[] params = cmd.getParams();
          AID sender = (AID)params[0];
          msg = (GenericMessage)params[1];
          AID receiver = (AID)params[2];
          Envelope env = msg.getEnvelope();
          SecurityObject so;
          // Actions on SecurityObject information
          if (env != null) {
            if ( (action.startsWith("signature")) && 
                 ((so=SecurityService.getSecurityObject(env,SecurityObject.SIGN)) != null) ) {
              SecurityData soi = soCodec.decode((byte[])so.getEncoded()); // Note: only supports Basic codec
              if (SIG_KEY.equals(action)) {
                // Change public key data
                SDSIName tmp = soi.key.getSDSIName();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(tmp.getAlgorithm());
                byte[] data = kpg.generateKeyPair().getPublic().getEncoded();
                JADEPrincipal k = new JADEPrincipalImpl(soi.key.getName(), 
                                                        new SDSINameImpl(data,tmp.getAlgorithm(),null,
                                                                         tmp.getLocalNames()));
                soi.key = k;
              }
              else if (SIG_KE2.equals(action)) {
                SDSIName tmp = soi.key.getSDSIName();
                // Change public key data with incorrect info
                byte[] data = new byte[tmp.getEncoded().length];
                rnd.nextBytes(data);
                JADEPrincipal k = new JADEPrincipalImpl(soi.key.getName(), 
                                                        new SDSINameImpl(data,tmp.getAlgorithm(),null,
                                                                         tmp.getLocalNames()));
                soi.key = k;
              }
              else if (SIG_KAL.equals(action)) {
                // Change public key algorithm 
                SDSIName tmp = soi.key.getSDSIName();
                JADEPrincipal k = new JADEPrincipalImpl(soi.key.getName(), 
                                                        new SDSINameImpl(tmp.getEncoded(),"DSA",null,
                                                                         tmp.getLocalNames()));
                soi.key = k;
              }
              else if (SIG_KA2.equals(action)) {
                // Change public key algorithm with an unsupported value
                SDSIName tmp = soi.key.getSDSIName();
                JADEPrincipal k = new JADEPrincipalImpl(soi.key.getName(), 
                                                        new SDSINameImpl(tmp.getEncoded(),"XXX",null,
                                                                         tmp.getLocalNames()));
                
                soi.key = k;
              }
              else if (SIG_VAL.equals(action)) {
                // Change signature value
                byte[] data = new byte[soi.data.length];
                rnd.nextBytes(data);
                soi.data = data;
              }
              else if (SIG_ALG.equals(action)) {
                // Change signature algorithm (supported but incorrect)
                soi.algorithm = "DSA";
              }
              else if (SIG_AL2.equals(action)) {
                // Change signature algorithm (unsupported)
                soi.algorithm = "XXX";
              }
              else if (SIG_PAY.equals(action)) {
                ACLMessage m = new ACLMessage(ACLMessage.INFORM);
                m.addReceiver(receiver);
                m.setSender(sender);
                m.setContent("Rogue content");
                msg.update(m,msg.getEnvelope(),aclCodec.encode(m,null));
              }
              so.setEncoded(soCodec.encode(soi));
              System.out.println("[RogueFilter] Secure message signature hacked");
            }
            else if ( (action.startsWith("encryption")) && 
                 ((so=SecurityService.getSecurityObject(env,SecurityObject.ENCRYPT)) != null) ) {
              SecurityData soi = soCodec.decode((byte[])so.getEncoded()); // Note: only supports Basic codec
              if (ENC_KEY.equals(action)) {
                // Change symmetric key to another value
                byte[] data = new byte[soi.data.length];
                rnd.nextBytes(data);
                soi.data = data;
              }
              else if (ENC_KE2.equals(action)) {
                // Change symmetric key to a non-valid value (wrong size)
                byte[] data = new byte[56];
                rnd.nextBytes(data);
                soi.data = data;
              }
              else if (ENC_ALG.equals(action)) {
                // Change signature algorithm to another value
                soi.algorithm = "DES";
                byte[] data = new byte[56];
                rnd.nextBytes(data);
                soi.data = data;
              }
              else if (ENC_AL2.equals(action)) {
                // Change signature algorithm (unsupported)
                soi.algorithm = "XXX";
              }
              else if (ENC_PAY.equals(action)) {
                // Change the encrypted payload
                byte[] data = new byte[msg.getPayload().length];
                rnd.nextBytes(data);
                msg.update(msg.getACLMessage(),msg.getEnvelope(),data);
              }
              so.setEncoded(soCodec.encode(soi));
              System.out.println("[RogueFilter] Secure message encryption hacked");
            }
          }
        }
        catch(Exception e) {
          e.printStackTrace();
          cmd.setReturnValue(e);
          return false;
        }
      }
      return true;
    }
    
  } // End of RogueFilter class
  

  /* ************************************************************
   *   Dummy implementation of Service Sink and Slice interfaces
   * ************************************************************/

  public Class getHorizontalInterface() {
    return null;
  }

  public Service.Slice getLocalSlice() {
    return null;
  }

  public Sink getCommandSink(boolean side) {
    return null;
  }

  public String[] getOwnedCommands() {
    return null;
  }

}
