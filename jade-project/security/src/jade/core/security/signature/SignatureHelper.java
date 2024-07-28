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
package jade.core.security.signature;

import jade.core.Agent;

import jade.lang.acl.ACLMessage;

import jade.security.JADEAuthority;
import jade.security.JADEPrincipal;

import jade.security.impl.JADEAuthorityImpl;


/**
 * This class provides an agent methods for accessing
 * ACL message signing.
 * Real signature calculation and verification is performed
 * into the filter of the SecurityService.
 *
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @version  $Date: 2004-09-22 15:10:30 +0200 (mer, 22 set 2004) $ $Revision: 510 $
 *
 * @see jade.core.security.signature.SignatureService
 */
public class SignatureHelper implements jade.core.ServiceHelper {
    // the agent "owning" this SecurityServiceExecutor
    private Agent myAgent = null;

    // the default authority
    private JADEAuthorityImpl authority = null;

    /**
     *   This must be called in order to initialize the SecurityServiceExecutor.
     *
     *   Configuration parameters are read from the JADE properties.
     *
     */
    public void init(Agent a) {
        System.out.println("SignH: init() ");

        // link this sh to an agent
        myAgent = a;
    } // end init()
      /*
       Say that the given ACLMessage will have to be signed
       (before leaving the container) by using the own private key
    */
    public void setForSignature(ACLMessage msg) {
        // - get the envelope from the msg (or create a new one)
        // - get the SecurityObject (for now serialized into x-security user-def property)
        // - set the toBeSigned bit of the SecurityObject
        // @@ Fixme
        System.out.println(
            " SecurityManager.setForSignature() Not Implemented yet.");
    }

    /**
     *   Check whether the given ACLMessage will have to be signed
     *         (before leaving the container) by using the own private key
     */
    public boolean isForSignature(ACLMessage msg) {
        // - get the envelope from the msg (if doesn't have one, return false)
        // - get the SecurityObject (for now serialized into x-security user-def property)
        // -  (if it doesn't have a SecurityObject, return false)
        // - return the toBeSigned bit of the SecurityObject
        System.out.println(
            " SecurityManager.isForSignature() Not Implemented yet.");

        // @@ Fixme
        return false;
    }

    /**
     *   Verify signature with the own public key
     */
    public boolean verifiedSignature(ACLMessage msg) {
        return verifiedSignature(msg, authority.getJADEPrincipal());
    }

    /**
     *   Verify signature with a given public key
     */
    public boolean verifiedSignature(ACLMessage msg, JADEPrincipal p) {
        // - get the envelope from the msg  (if doesn't have one, return false)
        // - get the SecurityObject (for now serialized into x-security user-def property)
        // - return the value of the "verified" field into the SecurityObject
        // @@ Fixme
        System.out.println(
            " SecurityManager.verifiedSignature() Not Implemented yet.");

        return false;
    }
} // end SignatureHelper class
