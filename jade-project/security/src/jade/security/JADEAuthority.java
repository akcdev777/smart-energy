/*****************************************************************
JADE - Java Agent DEvelopment Framework is a framework to develop
multi-agent systems in compliance with the FIPA specifications.
Copyright (C) 2002 TILAB S.p.A.

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

package jade.security;

import jade.core.Agent;
import jade.core.Profile;
import jade.domain.FIPAAgentManagement.SecurityObject;
import jade.security.util.SecurityData;

/**
 * The <code>Authority</code> interface represents an authority.
 * It has methods for signing certificates and for
 * verifying their validity.
 *
 * @author Giosue Vitaglione - Telecom Italia LAB
 * @author Nicolas Lhuillier - Motorola
 * @version $Date: 2004-07-21 17:18:27 +0200 (mer, 21 lug 2004) $ $Revision: 459 $
*/
public interface JADEAuthority {
  
  /**
   * Initialize the authority for the given agent.
   */
  //oid init(Agent myAgent, Credentials creds) throws Exception ;
  
  /**
   * Initialize the authority by reading the configuration parameters 
   * from the Profile
   */
  void init(String authorityName, Profile prof, Credentials creds) throws Exception;
  
  /**
   * Returns the JADEPrincipal for this Authority
   */
  JADEPrincipal getJADEPrincipal();
  
  /**
   * Signs the raw text following the information (e.g. algorithm, etc.)
   * contained in the SecurityObject and place the signature in the SecurityObject.
   * @return the signature
   */
  SecurityData sign(String algorithm, byte[] text) throws JADESecurityException;

  /**
   * Verify that the signature contained in the SecurityObject is a valid signature 
   * for the given text.
   */
  boolean verifySignature(SecurityData signature, byte[] text) throws JADESecurityException;

  /**
   * Encrypt the clear <code>text</code> using the information 
   * (e.g. algorithm, strength, etc.) contained in the SecurityObject 
   * for the given Principal (i.e. using this Principal's public-key).
   * @return the encrypted text
   */
  byte[] encrypt(SecurityObject so, byte[] text, JADEPrincipal recKey) throws Exception;
  
  /**
   * Decrypt the obfucated text <code>enc</code>, using the information (e.g. wrapped-key, etc.)
   * contained in the SecurityObject.
   * Note that this method uses this authority's public-key to unwrap the symmetric encryption key.
   */
  byte[] decrypt(SecurityObject so, byte[] enc) throws Exception;


  /**
     Checks the validity of a given certificate.
     The period of validity is tested, as well as the integrity
     (verified using the carried signature as proof).
     No verification is performed on the content (e.g. names, permission, delegations, etc.)
     @param cert The certificate to verify.
     @throws AuthenticationException if the certificate is not
     integer or is out of its validity period.
  */
  /*
    public void verify(JADECertificate certificate) throws JADESecurityException;
  */
  /**
     Sign the given certificate.
     @param cert The certificate to sign.
     @throws JADESecurityException
  */
  /*
    public void sign(JADECertificate certificate) throws JADESecurityException;
  */
}
