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

import jade.core.AgentContainer;
import jade.core.Command;
import jade.core.Profile;
import jade.core.security.permission.CommandChecker;
import jade.core.security.permission.PermissionService;
import jade.security.Credentials;
import jade.security.JADEAccessController;
import jade.security.JADEPrincipal;
import jade.security.JADESecurityException;
import jade.util.Logger;

import java.security.Permission;
import java.util.Hashtable;


/**
 *
 *
 *  If you want to create a checker for certain Command types
 *  you can extends this abstract class, implementing the
 *  abstract check() method. Into the implementation of this method
 *  you will usually retrieve all the needed information from the
 *  Command you are processing, and call the method:
 *   checkAction(subject, permission, action, target, certs);
 *
 *
 *   @author Giosue Vitaglione - Telecom Italia LAB
 *   @see jade.core.security.permission.PermissionService
 */
abstract public class BaseJADEChecker implements CommandChecker {


	protected static JADEAccessController defaultJADEAccessController=null;
	protected static Profile defaultProfile=null;
	protected static AgentContainer myDefaultContainer=null;
	protected static PermissionService defaultPermservice = null;

//	contains rows composed by: command-type, permission, action
	private Hashtable table = new Hashtable();

//	access controller wrapping the used container's policy
	protected JADEAccessController ac = null;
	protected Profile p = null;
	protected AgentContainer myContainer = null;  
	protected PermissionService service = null;

	protected Logger myLogger = Logger.getMyLogger(this.getClass().getName());

	protected boolean direction;
	public void setDirection(boolean direction){ this.direction=direction; }

	public BaseJADEChecker() {
		this.p = defaultProfile;
		this.ac = defaultJADEAccessController;
		this.myContainer = myDefaultContainer;
		this.service = defaultPermservice;
	}

	public BaseJADEChecker( Profile p, PermissionService permservice, JADEAccessController ac ) {
		this.p = p;
		this.service = permservice;
		this.ac = ac;
	}

	public static void setDefaultJADEAccessController(JADEAccessController ac){
		defaultJADEAccessController=ac;
	}
	public static void setDefaultProfile(Profile myProfile) {
		defaultProfile = myProfile;
	}
	public static void setDefaultContainer(AgentContainer ac) {
		myDefaultContainer = ac;
	}
	public static void setDefaultPermissionService(PermissionService permservice) {
		defaultPermservice = permservice;
	}








	public void checkAction(JADEPrincipal subject,
			Permission permission, 
			JADEPrincipal target,
			Credentials creds) throws JADESecurityException {

		ac.checkAction( subject, permission, target, creds );
		// Note: for now a single JADEAccessController checks against a single policy

	} // end check




	/**
	 *
	 * Implement the check(Command) so that:
	 *  takes the cmd, gets the required info from the cmd parameters
	 *  calls the method: check(subject, permission, action, target, credential)
	 *
	 */
	abstract public void check(Command cmd) throws JADESecurityException;

} // end checker class


