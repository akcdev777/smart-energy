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

package jade.core.security.permission.checkers;

import jade.core.AID;
import jade.core.Agent;
import jade.core.AgentState;
import jade.core.Command;
import jade.core.ContainerID;
import jade.core.Filter;
import jade.core.GenericCommand;
import jade.core.IMTPException;
import jade.core.NodeDescriptor;
import jade.core.Service;
import jade.core.ServiceException;
import jade.core.NotFoundException;
import jade.core.management.AgentManagementSlice;
import jade.core.security.SecurityHelper;
import jade.core.security.SecurityService;
import jade.core.security.authentication.OwnershipCertificate;
import jade.core.security.authentication.UserAuthenticator;
import jade.core.security.authentication.UserPassCredential;
import jade.core.security.permission.PermissionFilter;
import jade.security.AMSPermission;
import jade.security.AgentPermission;
import jade.security.AuthPermission;
import jade.security.CertificateEncodingException;
import jade.security.ContainerPermission;
import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.security.PlatformPermission;
import jade.security.util.SecurityData;
import jade.util.Logger;

import java.security.Permission;

/**
 *
 *
 *  A <code>SimpleCommandChecker </code>
 *  object maps Command types to couples: (Permission, action)
 *  where Permission is the name of the Permission class
 *  and action is the action to be checked against the policy.
 *
 *   @author Giosue Vitaglione - Telecom Italia LAB
 *   @version  $Date: 2016-02-15 12:41:14 +0100 (lun, 15 feb 2016) $ $Revision: 2054 $
 * 
 *   @see jade.core.security.permission.PermissionService
 */
public class SimpleJADEChecker extends BaseJADEChecker {


	/**
	 *
	 * Implement the check(Command) so that:
	 *  takes the cmd, gets the required info from the cmd parameters
	 *  calls the method: check(subject, permission, target, credential)
	 *
	 */
	public void check(Command cmd) throws JADESecurityException {
		String name = cmd.getName();
		Object[] params = cmd.getParams(); 
		JADEPrincipal requester = cmd.getPrincipal();
		Credentials creds = cmd.getCredentials();
		OwnershipCertificate requesterOc = null;
		if (creds == null && requester != null) {
			// If the requester does not show any credentials, use his ownership cert
			requesterOc = (OwnershipCertificate) service.getOwnershipCertificate(requester);
			creds = (OwnershipCertificate) requesterOc;
		}

		Permission permission = null;
		if (name.equals(Service.NEW_NODE)) {
			// Main container: NEW_NODE UP command issued by the underlying PlatformManagerImpl.
			// The requester principal and credentials 
			// are held by the NodeDescriptor and not by the command.
			jade.core.security.permission.PermissionFilter.log( direction, cmd );

			NodeDescriptor nd = (NodeDescriptor) params[0];
			String container_name = nd.getName();
			requester = nd.getOwnerPrincipal();
			creds = nd.getOwnerCredentials();

			if ( nd.getNode().hasPlatformManager() ) {
				// Node holds a Main container: Check if the requester is authorized to create a platform.
				myLogger.log(Logger.FINE, "  NEW_NODE ("+nd.getName()+")  p="+requester+" c="+creds);
				permission = new PlatformPermission( "", "create");
				checkAction( requester, permission, null, creds );
			} 
			else {
				// Node holds a Peripheral container: authenticate the user on the basis of his username and password
				authenticateRemoteUser(nd.getUsername(), nd.getPassword());        
			}

			// Check if the requester is autorized to create a container owned by himself.
			myLogger.log(Logger.FINE, "  NEW_NODE ("+nd.getName()+")  p="+requester+" c="+creds);
			permission = new ContainerPermission(ContainerPermission.CONTAINER_OWNER+"="+requester.getName(), "create");
			checkAction( requester, permission, null, creds );
		}
		else if (name.equals(Service.DEAD_NODE)) {
			// FIXME: Should we perform some check?
		}
		else if (name.equals(AgentManagementSlice.SHUTDOWN_PLATFORM)) {
			if (direction == Filter.OUTGOING) {
				// Main container: SHUTDOWN_PLATFORM DOWN command issued by the AMS on behalf of a requester
				jade.core.security.permission.PermissionFilter.log( direction, cmd );
				permission = new PlatformPermission( "", "kill");
				checkAction( requester, permission, null, creds );
			}
		}
		else if (name.equals(AgentManagementSlice.KILL_CONTAINER)) {
			if (direction == Filter.OUTGOING) {
				// Main container: KILL_CONTAINER DOWN command issued by the AMS on behalf of a requester
				jade.core.security.permission.PermissionFilter.log( direction, cmd );
	
				ContainerID cid = (ContainerID) params[0];
				try {
					String containerOwner = service.getContainerOwner(cid).getName();
	
					// Check if the requester is authorized to kill a container owned by a given owner.
					permission = new ContainerPermission(ContainerPermission.CONTAINER_OWNER+"="+containerOwner, "kill");				
					checkAction( requester, permission, null, creds );
				}
				catch (NotFoundException nfe) {
					// We are killing a node that does not exist 
					// --> just do nothing. Operation will fail.
				}
			}
			else {
				// Peripheral container: KILL_CONTAINER UP Command received from the Main
				
				// FIXME: Which permission should we check????
			}
		}
		else if (name.equals(AgentManagementSlice.REQUEST_CREATE)) {
			jade.core.security.permission.PermissionFilter.log( direction, cmd );

			String agentName = null;
			String containerOwner = null;
			int ownerIndex = -1;
			if (direction == Filter.OUTGOING) {
				agentName = (String) params[0];
				ContainerID cid = (ContainerID) params[3];
				try {
					containerOwner = service.getContainerOwner(cid).getName();
				}
				catch (NotFoundException nfe) {
					// We are trying to create an agent on a container that does not exist
					// --> just do nothing. Operation will fail
				}
				ownerIndex = 4;
			}
			else {
				AID agentID = (AID) params[0];
				agentName = agentID.getName();
				ownerIndex = 3;
			}

			String className = (String) params[1];
			JADEPrincipal owner = null;
			Credentials initialCredentials = null;

			owner = (JADEPrincipal) params[ownerIndex];
			initialCredentials = (Credentials) params[ownerIndex+1];
			if (owner == null && requesterOc != null) {
				// If no owner is specified, use the owner of the requester
				owner = requesterOc.getOwner();
				params[ownerIndex] = owner;
				adjustCommandParams((GenericCommand) cmd, params);
			}

			String ownerName = "NONE";
			if (owner != null) {
				ownerName = owner.getName();
			}

			// Check if the requester is autorized to creatre an agent of class className, with name agentName owned by ownerName
			permission = new AgentPermission( AgentPermission.AGENT_CLASS+"="+className+","+
					AgentPermission.AGENT_NAME+"="+agentName+","+
					AgentPermission.AGENT_OWNER+"="+ownerName+","+
					AgentPermission.CONTAINER_OWNER+"="+containerOwner 
					, "create");
			checkAction( requester, permission, null, creds );
		} 
		else if (name.equals(AgentManagementSlice.INFORM_CREATED)) {
			jade.core.security.permission.PermissionFilter.log( direction,  cmd );

			if (direction == Filter.OUTGOING) {
				// Baptize the agent i.e. creates its principal and credentials
				Agent createdAgent = (Agent) params[1]; 
				JADEPrincipal owner = (JADEPrincipal) params[2];
				Credentials initialCreds = (Credentials) params[3];

				SecurityHelper sh = baptism( createdAgent, owner ); 
				JADEPrincipal agentPrincipal = sh.getPrincipal();
				Credentials agentCreds = sh.getCredentials();

				// The requester in this case is the newly started agent --> 
				// insert hist principal and credentials into the INFORM_CREATED VC.
				cmd.setPrincipal( agentPrincipal );
				cmd.setCredentials( agentCreds );
				myLogger.log(Logger.FINER, "\n    agent=("+agentPrincipal+")"+ 
						"\n    owner=("+agentCreds.getOwner()+")");

				// check if the agent (and not the requestor) has got the permission
				if (agentPrincipal==null) {
					String msg = " Internal error,  null agentPrincipal after agent creation.";
					myLogger.log(Logger.WARNING, msg );
					throw new JADESecurityException( msg );
				} 
			}
			else {
				// Check that the requester (a newly started agent) is authorized 
				// to register with the AMS.
				AID createdAgentID = (AID) params[0];
				String agentName = createdAgentID.getName();
				String ownerName = (creds != null) ? creds.getOwner().getName() : "NONE";

				permission = new AMSPermission( AMSPermission.AGENT_NAME+"="+agentName+","+
						AMSPermission.AGENT_OWNER+"="+ownerName 
						, "register");

				checkAction(requester, permission, null, creds);
			}

		} 
		else if (name.equals(AgentManagementSlice.REQUEST_KILL)) {
			jade.core.security.permission.PermissionFilter.log( direction, cmd );

			AID killedAgentID = (AID) params[0];
			Agent agent = null; // agent to be killed
			String className = "";
			JADEPrincipal victim = null;
			String victim_owner_name = "";
			String victim_name = killedAgentID.getName();

			// get the owner of the agent to kill
			OwnershipCertificate oc_victim = (OwnershipCertificate) service.getOwnershipCertificate( victim_name );
			if (oc_victim!=null) {
				victim_owner_name = oc_victim.getOwner().getName();
			}

			agent = myContainer.acquireLocalAgent(killedAgentID);
			if (agent!=null) { className = (String) agent.getClass().getName();  }
			myContainer.releaseLocalAgent(killedAgentID);

			// FIXME: Check CONTAINER_OWNER to

			if (agent!=null) {
				// agent is on this container
				permission = new AgentPermission( AgentPermission.AGENT_CLASS+"="+className+","+
						AgentPermission.AGENT_OWNER+"="+victim_owner_name+","+
						AgentPermission.AGENT_NAME+ "="+victim_name 
						, "kill");
			} else {
				// agent is not on this container
				permission = new AgentPermission( AgentPermission.AGENT_OWNER+"="+victim_owner_name+","+ 
						AgentPermission.AGENT_NAME+ "="+victim_name 
						, "kill");
			}
			checkAction( requester, permission, null, creds );

		} 
		else if (name.equals(AgentManagementSlice.INFORM_KILLED)) {
			jade.core.security.permission.PermissionFilter.log( direction, cmd );

			if (direction == Filter.INCOMING) {
				// Check that the requester (a just dead agent) is authorized 
				// to deregister from the AMS.
				AID killedAgentID = (AID) params[0];
				String agentName = killedAgentID.getName();
				permission = new AMSPermission(AMSPermission.AGENT_NAME+"="+agentName, "deregister");
				// FIXME: Should we enable this check?
				// checkAction( requester, permission, null, creds );
			}

		} 
		else if (name.equals(AgentManagementSlice.REQUEST_STATE_CHANGE)) {
			jade.core.security.permission.PermissionFilter.log( direction, cmd );

			AID targetID = (AID) params[0];
			String target_name = targetID.getName();
			int requestedState = ((AgentState) params[1]).getValue();

			String action="";
			switch(requestedState) {
			case Agent.AP_SUSPENDED:
				action="suspend"; 
				break;
			case Agent.AP_ACTIVE:
				action="resume";  
				break;
			case Agent.AP_WAITING:
				// No check to perform!
				return;
			}

			// Get the owner of the agent the requester wants to change state to
			String target_owner_name = "";
			OwnershipCertificate oc_target = (OwnershipCertificate) service.getOwnershipCertificate( target_name );
			if (oc_target != null) {
				target_owner_name = oc_target.getOwner().getName();
			}

			// Get the target agent class name if it is in the lovcal container
			String targetClassName = "";
			Agent target = myContainer.acquireLocalAgent(targetID);
			if (target != null) { 
				targetClassName = target.getClass().getName();
			}
			myContainer.releaseLocalAgent(targetID);

			// FIXME: Check CONTAINER_OWNER to

			if (target != null) {
				// agent is on this container
				permission = new AgentPermission( AuthPermission.AGENT_CLASS+"="+targetClassName+","+
						AuthPermission.AGENT_OWNER+"="+target_owner_name+","+
						AuthPermission.AGENT_NAME+ "="+target_name 
						, action);
			} else {
				// agent is not on this container
				permission = new AgentPermission( AuthPermission.AGENT_OWNER+"="+target_owner_name+","+ 
						AuthPermission.AGENT_NAME+ "="+target_name 
						, action);
			}
			checkAction( requester, permission, null, creds );
		}
	}



	private SecurityHelper amsAutoBaptism (Agent createdAgent, JADEPrincipal owner) throws JADESecurityException {
		// The AMS agent baptize itself, with this special procedure

		SecurityHelper ams_sh=null;
		try { 
			// retrieve ams principal
			ams_sh = (SecurityHelper) createdAgent.getHelper(jade.core.security.SecurityService.NAME);
			ams_sh.init(createdAgent);
		} catch (ServiceException ex) {
			throw new JADESecurityException (" Service problems in creating Agent's OwnershipCertificate. ");
		}

		// create the OwnershipCertificate
		OwnershipCertificate amsOwnCert = new OwnershipCertificate( 
				ams_sh.getPrincipal(), // ams principal
				owner );           // ams owner principal

		// self-sign the cert
		// calculates the signature
		SecurityData sd = new SecurityData();
		byte[] encCert = null;
		try {
			encCert = amsOwnCert.getEncoded();
		} catch(CertificateEncodingException cee) {
			throw new JADESecurityException("CertificateEncodingException when trying to sign (by the AMS) a certificate. ");
		}

		sd = ams_sh.getAuthority().sign(ams_sh.getSignatureAlgorithm(), encCert);

		// put the signature into the NameCertificate
		amsOwnCert.setSignature(sd);

		// keep the AMS OwnershipCertificate
		service.setAMSOwnershipCertificate( amsOwnCert );
		ams_sh.addCredentials( amsOwnCert ); // add the Ownership Certificate

		return ams_sh;
	}


	private SecurityHelper baptism (Agent createdAgent, JADEPrincipal owner) throws JADESecurityException {

		if (createdAgent instanceof jade.domain.ams) {
			// the ams is special, it self-baptizes
			return amsAutoBaptism( createdAgent, owner);
		}

		// all normal agents are baptized by the platform's AMS

		// agent principal (got from the sh) and credentials (OwnershipCertificate)
		SecurityHelper sh=null;
		try { 
			// retrieve agent's principal
			sh = (SecurityHelper) createdAgent.getHelper(jade.core.security.SecurityService.NAME);
			sh.init(createdAgent);
		} catch (ServiceException ex) {
			throw new JADESecurityException (" Service problems in creating Agent's OwnershipCertificate. ");
		}

		// create the OwnershipCertificate
		OwnershipCertificate ownershipCert = 
			service.getOwnershipCertificate(
					sh.getPrincipal(), // agent principal
					owner );           // owner principal

		sh.addCredentials( ownershipCert ); // add the Ownership Certificate

		return sh;
	} // end baptism


	private void authenticateRemoteUser( String username, byte[] password ) throws JADESecurityException {

		// authenticate user by using the Main container authentication module
		UserAuthenticator ua = new UserAuthenticator(
				(service.getProfile().getParameter(SecurityService.AUTHENTICATION_LOGINMODULE_KEY, null)),
				(service.getProfile().getParameter(SecurityService.AUTHENTICATION_LOGINCALLBACK_KEY, null)),
				(service.getProfile().getParameter(SecurityService.AUTHENTICATION_OWNER_KEY, null)), false);

		try {
			// authenticate the user who is requesting the join 
			// of a remote container
			ua.login(new UserPassCredential(username, password));
		} catch (Exception ex2) {
			throw new JADESecurityException("Username Authentication FAILED.");
		}
	}

	private Object fixOwner(Command cmd) {
		Object returnValue=null;
		// requester did not tell the owner => 
		// => assume the owner the same as the requester's owner
		//  requester's agentPrincipal -> owner
		JADEPrincipal requester = cmd.getPrincipal();
		Credentials creds = cmd.getCredentials();

		JADEPrincipal reqOwner=null;

		OwnershipCertificate oc = (OwnershipCertificate) service.getOwnershipCertificate(requester);
		if (oc!=null) reqOwner=oc.getOwner();

		if (reqOwner==null) { 
			// avoid loop
			returnValue = new JADESecurityException("Agent creation request had 'null' owner, and owner was not known.");
		} else {

			if (creds==null) {
				// if the requester does not show any his creds, pass his ownership cert (since we have it here...)
				creds = (OwnershipCertificate) oc;
			}
			// create a new cmd, that "replaces" the current cmd
			GenericCommand cmd2 = new GenericCommand(cmd.getName(),cmd.getService(),null);
			cmd2.setPrincipal(requester);
			cmd2.setCredentials(creds);
			Object[] params = cmd.getParams(); 
			cmd2.addParam( params[0] );
			cmd2.addParam( params[1] );
			cmd2.addParam( params[2] );
			cmd2.addParam( params[3] );
			cmd2.addParam( (JADEPrincipal) reqOwner );
			cmd2.addParam( (Credentials) null ); // initial creds

			// feed the new cmd into the service chain
			try {
				Service amserv = myContainer.getServiceFinder().findService(jade.core.management.AgentManagementSlice.NAME);

				returnValue = amserv.submit(cmd2);
			} catch (ServiceException ex) {
				returnValue = new JADESecurityException("Agent creation request had 'null' owner, service exception while trying to retrieve it.");
			} catch (IMTPException ex1) {
				returnValue = new JADESecurityException("Agent creation request had 'null' owner, IMTP exception while trying to retrieve it.");
			}

		} // end if-else reqOwner==null

		return returnValue;
	}// end fixOwner


	private void adjustCommandParams(GenericCommand gCmd, Object[] params) {
		gCmd.clear();
		for (int i = 0; i < params.length; ++i) {
			gCmd.addParam(params[i]);
		}
	}
} // end checker class
