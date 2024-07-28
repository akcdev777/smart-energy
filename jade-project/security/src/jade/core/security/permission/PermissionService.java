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

package jade.core.security.permission;

//#MIDP_EXCLUDE_FILE

import jade.core.Service;
import jade.core.BaseService;
import jade.core.Sink;
import jade.core.Filter;
import jade.core.Profile;
import jade.core.AgentContainer;
import jade.core.ProfileException;
import jade.core.ContainerID;
import jade.core.NodeDescriptor;
import jade.core.NotFoundException;
import jade.core.MainContainer;
import jade.core.security.authentication.NameCertificate;
import jade.security.JADEPrincipal;
import jade.security.CertificateEncodingException;
import jade.security.impl.BasicCertificateImpl;
import jade.core.Node;
import jade.core.VerticalCommand;
import jade.core.HorizontalCommand;
import jade.core.ServiceException;
import jade.core.IMTPException;
import jade.security.impl.NameAuthority;
import jade.core.AID;
import jade.core.AgentDescriptor;
import java.util.Hashtable;
import jade.security.JADEAccessController;
import jade.security.SecurityFactory;
import jade.security.JADESecurityException;
import jade.security.JADEAuthority;
import jade.core.Agent;
import jade.core.security.SecurityHelper;
import jade.core.security.SecurityService;
import jade.security.util.SecurityData;
import jade.util.Logger;
import jade.core.security.authentication.OwnershipCertificate;
import java.util.Enumeration;
import java.io.*;
import jade.security.impl.JADEAccessControllerImpl;




/**

   The JADE service to manage authorization for platform services

   @author Giosue Vitaglione - Telecom Italia LAB
 */
public class PermissionService 
extends BaseService 
implements NameAuthority {


	public static final String POLICY_FILE_KEY = "java.security.policy";
	public static final String POLICY_FILE_DEFAULT = "policy.txt";

	public static final String SECURITY_MANAGER_KEY = "jade_security_manager";
	public static final String SECURITY_MANAGER_DEFAULT = "jade.core.security.JADESecurityManager";
	public static final String SECURITY_MANAGER_NULL = "null"; // special value: no sec.man is installed.

	private static final String PERM_FILTER_CLASS_KEY = "jade_core_security_permission_filterClass";
	private static final String PERM_FILTER_CLASS_DEFAULT = "jade.core.security.permission.PermissionFilter";


	// The concrete agent container, providing access to LADT, etc.
	private AgentContainer myContainer;
	private Profile myProfile;
	private static Logger myLogger = Logger.getMyLogger(PermissionService.class.getName());

	// mapping: username<->principal
	// this probably should go into a new SecurityFilter (or AuthenticationFilter?)
	private Hashtable users = new Hashtable();

	// the filter performing the real authorization check
	private PermissionFilter permFilterUp = null;
	private PermissionFilter permFilterDown = null;    

	// unique for both filters, it is instantiated the first time you call getJADEAccessController()
	private JADEAccessController myJADEAccessController = null;

	static final String NAME = "jade.core.security.permission.Permission";
	public String getName() {
		return PermissionService.NAME;
	}


	public void init(AgentContainer ac, Profile profile) throws ProfileException {
		super.init(ac, profile);

		myContainer = ac;
		myProfile = profile;
		
		myLogger.log( Logger.INFO, "PermissionService initializing....");
		
		String policyFileName = myProfile.getParameter(POLICY_FILE_KEY, POLICY_FILE_DEFAULT);
		myLogger.log( Logger.INFO, "Loading security policy from file: "+policyFileName);
		// Check that the indicated policy file exists
		if (!(new File(policyFileName).exists())) {
			myLogger.log( Logger.SEVERE, "Security policy file not found: "+policyFileName);
		}

		// Set the java.security.policy System property to the indicated policy file
		System.setProperty(POLICY_FILE_KEY, policyFileName);

		// Set security manager for this Java Virtual Machine
		setSecurityManager();

		// PermissionFilter class
		String permFilterClass = myProfile.getParameter( PERM_FILTER_CLASS_KEY, PERM_FILTER_CLASS_DEFAULT);

		// create and initialize the filters of this service
		try {
			permFilterDown = (PermissionFilter) Class.forName(permFilterClass).
			newInstance();
			permFilterDown.init( this, myContainer, myProfile, Filter.OUTGOING );
			permFilterUp = (PermissionFilter) Class.forName(permFilterClass).newInstance();
			permFilterUp.init( this, myContainer, myProfile, Filter.INCOMING );
		} catch (Throwable ex) {
			throw new ProfileException ("Unable to create permission filter: "+permFilterClass+
					"\n (check config parameter: "+PERM_FILTER_CLASS_KEY, ex);
		}

	} // end init

	public void boot(Profile profile) throws ServiceException {
		super.boot(profile);
		myProfile = profile;

		// if this is a remote container
		// get from the main the (self signed) NameCertificate of the AMS 
		retrieveAMSNameCertificate();
		JADEPrincipal amsPrincipal = getAMSJADEPrincipal();
		if (amsPrincipal!=null) {
			if (myLogger.isLoggable(Logger.FINE))
				myLogger.log( Logger.FINE, "getAMSJADEPrincipal=" + amsPrincipal.toString());
		}
	}

	// Set the indicated SecurityManager for the local JVM
	private void setSecurityManager() {
		String secman_class = myProfile.getParameter( SECURITY_MANAGER_KEY, SECURITY_MANAGER_DEFAULT);

		// if 'null' do not set any security manager
		if (secman_class.equals(SECURITY_MANAGER_NULL)) return;

		try {
			if (System.getSecurityManager() == null) {
				myLogger.log(Logger.INFO, "Installing JADESecurityManager.  ");
			}
			else {
				myLogger.log(Logger.INFO, "Replacing existing SecurityManager with a JADESecurityManager.  (" +System.getSecurityManager() + ")");
			}
			System.setSecurityManager( (SecurityManager) Class.forName(secman_class).newInstance() );
		}
		catch (Exception e) {
			myLogger.log(Logger.WARNING, "Error setting SecurityManager for the local JVM", e);
		}
	}


	NameCertificate amsNameCert = null;
	private void retrieveAMSNameCertificate(){
		if (myContainer.getMain() != null) {
			// this is the main
		} else {
			// this is a remote container, ask to the main
			NameAuthority nameAuthority = this;
			amsNameCert = nameAuthority.getNameCertificate( myContainer.getAMS().getName() );
		}
	}

	/**
	 *  Returns the JADEPrincipal of the AMS of the agent platform
	 */
	public JADEPrincipal getAMSJADEPrincipal(){
		JADEPrincipal amsPrincipal = null;
		if (amsNameCert!=null) {
			amsPrincipal = amsNameCert.getSubject();
		}
		return amsPrincipal;
	} 

	public void setAMSOwnershipCertificate( OwnershipCertificate amsOwnCert){
		((ServiceComponent) this.getLocalSlice()).setAMSOwnershipCertificate(amsOwnCert);
	}

	public Filter getCommandFilter(boolean direction) {
		// the same for incoming and for outgoing commands
		if (direction==Filter.OUTGOING) 
			return permFilterDown;
		else 
			return permFilterUp;
	}



	/* *****************************************************
	 *  Usage info 
	 * *****************************************************

     The Permissionilter retrieves the Main-Container's slice:

       PermissionSlice mainSlice = (PermissionSlice)getSlice(MAIN_SLICE);

     and calls the right method: 

       NameCertificate nc = mainSlice.getNameCertificate( jadePrincipal );

	 */



	/* *****************************************************
	 * PermissionService business methods
	 * implementation of NameAuthority interface
	 * *****************************************************/

	public NameCertificate getNameCertificate(JADEPrincipal principal) {
		NameCertificate nc=null;
		if (myContainer.getMain()!=null) {
			// this is the main, call directly the ServiceComponent
			nc = ( (PermissionSlice) getLocalSlice()).getNameCertificate(principal);
		} else {
			// retrieve the main's slice, and invoke the method on the slice
			PermissionSlice mainSlice = null;
			try {
				mainSlice = (PermissionSlice) getSlice(MAIN_SLICE);
			} catch (ServiceException ex) { }
			if (mainSlice!=null) {
				nc = mainSlice.getNameCertificate( principal );
			}
		}
		// verify the certificate signature
		try {
			verifyCertificateSignature(nc);
		} catch(JADESecurityException se) { nc=null; }
		return nc;
	}

	public NameCertificate getNameCertificate(String name) {
		NameCertificate nc=null;
		if (myContainer.getMain()!=null) {
			// this is the main, call directly the ServiceComponent
			nc = ((PermissionSlice)getLocalSlice()).getNameCertificate( name );
		} else {
			// retrieve the main's slice, and invoke the method on the slice
			PermissionSlice mainSlice = null;
			try {
				mainSlice = (PermissionSlice) getSlice(MAIN_SLICE);
			} catch (ServiceException ex) { }
			if (mainSlice!=null) {
				nc = mainSlice.getNameCertificate( name );
			}
		}
		// verify the certificate signature
		try {
			verifyCertificateSignature(nc);
		} catch(JADESecurityException se) { nc=null; }
		return nc;
	}

	private void verifyCertificateSignature(BasicCertificateImpl cert) 
	throws JADESecurityException {
		if (cert==null) {
			throw new JADESecurityException("Null certificate passed for signature verification.");
		};
		// for verification, any JADEAuthority object is good (verification is stateless)
		JADEAuthority ja = SecurityFactory.getSecurityFactory().newJADEAuthority();
		byte[] text = null;
		try {
			text = cert.encode();
		}
		catch (IOException ex) {
			throw new JADESecurityException(ex.getMessage());
		}
		SecurityData sd = new SecurityData();
		sd.key = cert.getIssuer(); // this is protected by the signature
		sd.algorithm = cert.getSignature().algorithm;
		sd.data = cert.getSignature().data;

		ja.verifySignature( sd, text );
	} // end verifyCertificateSignature





	public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned, JADEPrincipal owner) {
		OwnershipCertificate owc=null;
		if (myContainer.getMain()!=null) {
			// this is the main, call directly the ServiceComponent
			owc = ((PermissionSlice)getLocalSlice()).getOwnershipCertificate( owned, owner );
		} else {
			// retrieve the main's slice, and invoke the method on the slice
			PermissionSlice mainSlice = null;
			try {
				mainSlice = (PermissionSlice) getSlice(MAIN_SLICE);
			} catch (ServiceException ex) { }
			if (mainSlice!=null) {
				owc = mainSlice.getOwnershipCertificate( owned, owner );
			}
		}
		return owc;
	}

	public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned) {
		OwnershipCertificate owc=null;
		if (myContainer.getMain()!=null) {
			// this is the main, call directly the ServiceComponent
			owc = ((PermissionSlice)getLocalSlice()).getOwnershipCertificate( owned );
		} else {
			// retrieve the main's slice, and invoke the method on the slice
			PermissionSlice mainSlice = null;
			try {
				mainSlice = (PermissionSlice) getSlice(MAIN_SLICE);
			} catch (ServiceException ex) { }
			if (mainSlice!=null) {
				owc = mainSlice.getOwnershipCertificate( owned );
			}
		}
		return owc;
	}

	public OwnershipCertificate getOwnershipCertificate(String owned) {
		OwnershipCertificate owc=null;
		if (myContainer.getMain()!=null) {
			// this is the main, call directly the ServiceComponent
			owc = ((PermissionSlice)getLocalSlice()).getOwnershipCertificate( owned );
		} else {
			// retrieve the main's slice, and invoke the method on the slice
			PermissionSlice mainSlice = null;
			try {
				mainSlice = (PermissionSlice) getSlice(MAIN_SLICE);
			} catch (ServiceException ex) { }
			if (mainSlice!=null) {
				owc = mainSlice.getOwnershipCertificate( owned );
			}
		}
		return owc;
	}


	public JADEPrincipal getContainerOwner(ContainerID cid) throws NotFoundException {
		MainContainer mc = myContainer.getMain();
		if (mc != null) {
			NodeDescriptor nd = mc.getContainerNode(cid);
			return nd.getOwnerPrincipal();
		}
		else {
			// This is available on the main container only
			throw new NotFoundException("Not on main");
		}
	}

	public JADEAccessController getJADEAccessController() {
		if (myJADEAccessController==null) {
			// -- create the container JADEAccessController --

			// instantiate one only Access Controller associated to the service for both filters
			myJADEAccessController = ((jade.security.impl.JADESecurityFactory) SecurityFactory.getSecurityFactory()).newJADEAccessController(
					"ac-jade", 
					null, 
					System.getProperty(POLICY_FILE_KEY)
			);

			// the PermissionService acts also as NameAuthority
			( (JADEAccessControllerImpl) myJADEAccessController ).setNameAuthority( this );
		}

		return myJADEAccessController;
	}



	/* *****************************************************
	 *   slice-related stuff
	 * *****************************************************/

	private static final String[] OWNED_COMMANDS = new String[] {
		PermissionSlice.NAMECERT_REQ
	};


	private PermissionSlice localSlice = new ServiceComponent(this);

	public Service.Slice getLocalSlice() {
		return localSlice;
	}

	public Class getHorizontalInterface() {
		try {
			return Class.forName(PermissionService.NAME + "Slice");
		} catch(ClassNotFoundException cnfe) {
			return null;
		}
	}

	public Sink getCommandSink(boolean side) {
		return null;
	}

	public String[] getOwnedCommands() {
		return OWNED_COMMANDS;
	}

	// for the permission service we need to access to config params from many places
	// e.g. the filter and the chackers
	public Profile getProfile() {
		return myProfile;
	}







//	ServiceComponent is the local slice of the service
	private class ServiceComponent implements PermissionSlice {

		private PermissionService service;

		public ServiceComponent(PermissionService service){
			this.service = service;
		} // end constructor



		/* *****************************************************
		 *  implementation of the business methods
		 * *****************************************************/

		public NameCertificate getNameCertificate(JADEPrincipal principal) {

			// if this is not the main container, do nothing 
			if (myContainer.getMain()==null) return null;

			// from the given principal, get the sdsiname/pub.key 
			// enter the GADT with the sdsiname
			// get the correspondent name
			// create a NameCertificate with the principal and such name
			// sign the certificate with the platform/ams authority

			AID[] aid = myContainer.getMain().agentNames();
			if (aid==null) return null;

			JADEPrincipal foundPrincipal = null;
			boolean found=false;
			for (int i=0; (i<aid.length) && (!found); i++) {
				AgentDescriptor ad = myContainer.getMain().acquireAgentDescriptor( aid[i] );
				if (ad !=  null) {
					// get the principal of this agent
					JADEPrincipal jp = ad.getPrincipal();
					if (jp!=null) { 
						// compare the principal with the given principal
						if (jp.getSDSIName().equals(principal.getSDSIName())) {
							// found it!
							foundPrincipal = jp;
							found=true; // we assume there can be only one agent having that principal
						}
					}
					myContainer.getMain().releaseAgentDescriptor( aid[i] );
				}
			} // end for

			NameCertificate nameCertificate=null;
			if (foundPrincipal!=null) {
				nameCertificate = new NameCertificate( foundPrincipal );
			}

			// we should also check for users's principals as well



			// the AMS signs the NameCertificate
			try {
				signCertificate(nameCertificate);
			} catch (ServiceException srvex) { 
				nameCertificate=null;
			} catch (JADESecurityException secex) {
				nameCertificate=null;
			}

			// returns the correct certificate signed by the AMS, or 'null' if something went bad
			return nameCertificate;
		}



		private void signCertificate(BasicCertificateImpl cert) 
		throws JADESecurityException, ServiceException {
			if (cert==null) return;

			// retrieve AMS Security Helper
			AID amsID = myContainer.getAMS();
			Agent ams_agent = myContainer.acquireLocalAgent( amsID );
			SecurityHelper ams_sh = null;
			if (ams_agent!=null) {
				ams_sh = (SecurityHelper) ams_agent.getHelper(SecurityService.NAME);
				myContainer.releaseLocalAgent( amsID );
			} else {
				myContainer.releaseLocalAgent( amsID );
				throw new 
				ServiceException("signCertificate: No AMS Agent available to get SecurityHelper handle");
			}
			cert.setIssuer( ams_sh.getPrincipal() );

			// calculates the signature
			SecurityData sd = new SecurityData();
			byte[] encCert = null;
			try {
				encCert = cert.getEncoded();
			} catch(CertificateEncodingException cee) {
				throw new JADESecurityException("CertificateEncodingException when trying to sign (by the AMS) a certificate. ");
			}

			sd = ams_sh.getAuthority().sign(ams_sh.getSignatureAlgorithm(), encCert);

			// put the signature into the NameCertificate
			cert.setSignature(sd);

		} // end signNameCertificate



		public NameCertificate getNameCertificate(String name) {

			// if this is not the main container, do nothing 
			if (myContainer.getMain()==null) return null;

			AID[] aid = myContainer.getMain().agentNames();
			if (aid==null) return null;

			JADEPrincipal foundPrincipal = null;
			boolean found=false;
			for (int i=0; (i<aid.length) && (!found); i++) {
				AgentDescriptor ad = myContainer.getMain().acquireAgentDescriptor( aid[i] );
				// get the name of this agent
				JADEPrincipal jp = ad.getPrincipal(); 
				if (jp!=null) {
					// compare the principal with the given name
					if (jp.getName().equals( name )) {
						// found it!
						foundPrincipal = jp;
						found=true; // we assume there can be only one agent having that principal
					}
				}
				myContainer.getMain().releaseAgentDescriptor( aid[i] );
			} // end for

			NameCertificate nameCertificate=null;
			if (foundPrincipal!=null) {
				nameCertificate = new NameCertificate( foundPrincipal );
			}

			// we should also check for users's principals as well



			// the AMS signs the NameCertificate
			try {
				signCertificate(nameCertificate);
			} catch (ServiceException srvex) { 
				nameCertificate=null;
			} catch (JADESecurityException secex) {
				nameCertificate=null;
			}

			// returns the correct certificate signed by the AMS, or 'null' if something went bad
			return nameCertificate;
		}















		// contains the OwnershipCertificate created here
		Hashtable ownershipTable = new Hashtable();

		public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned) {
			// request the OwnershipCertificate of a previously created agent

			// if this is not the main container, do nothing 
			if (  (myContainer.getMain()==null) 
					|| (owned==null) ) {
				return null;
			}

			// find the owner of 'owned'
			OwnershipCertificate ownCertificate=null;
			// get the copy of the cert from the local ownershipTable
			ownCertificate = (OwnershipCertificate) ownershipTable.get( owned );

			return ownCertificate;
		} // end getOwnershipCertificate


		public OwnershipCertificate getOwnershipCertificate(String owned) {
			// request the OwnershipCertificate of a previously created agent

			// if this is not the main container, do nothing 
			if (myContainer.getMain()==null) return null;

			// find the owner of 'owned'
			OwnershipCertificate ownCertificate=null;
			// get the copy of the cert from the local ownershipTable
			Enumeration enumK = ownershipTable.keys();
			for (; enumK.hasMoreElements();){
				JADEPrincipal jp = (JADEPrincipal) enumK.nextElement();
				if ( jp.getName().equals( owned ) ){
					ownCertificate = (OwnershipCertificate) ownershipTable.get( jp );
				}
			}

			return ownCertificate;
		} // end getOwnershipCertificate


		public OwnershipCertificate getOwnershipCertificate(JADEPrincipal owned, JADEPrincipal owner) {
			// create the own certificate and register it into the main ownershipTable

			// if this is not the main container, do nothing 
			if (myContainer.getMain()==null) return null;

			// create the cert
			OwnershipCertificate ownCertificate=null;
			ownCertificate = new OwnershipCertificate( owned, owner );

			// keep copy of the cert into the local ownershipTable
			ownershipTable.put( owned, ownCertificate );

			// the AMS signs the OwnershipCertificate
			try {
				signCertificate(ownCertificate);
			} catch (ServiceException srvex) { 
				ownCertificate=null;
			} catch (JADESecurityException secex) {
				ownCertificate=null;
			}

			// returns the correct certificate signed by the AMS, or 'null' if something went bad
			return ownCertificate;
		}

		// used while ams self-baptize
		public void setAMSOwnershipCertificate( OwnershipCertificate amsOwnCert){
			JADEPrincipal ams = amsOwnCert.getSubject();
			OwnershipCertificate existing_amsOwnCert = getOwnershipCertificate( ams );
			if (existing_amsOwnCert==null) {
				ownershipTable.put( amsOwnCert.getSubject(), amsOwnCert );
			}
		}






		public Service getService() {
			return service;
		}

		public Node getNode() throws ServiceException {
			try {
				return service.getLocalNode();
			} catch(IMTPException imtpe) {
				throw new ServiceException("Problem in contacting the IMTP Manager", imtpe);
			}
		}

		public VerticalCommand serve(HorizontalCommand hcmd) {
			// received a h-cmd -> think/act -> setRetVal -> (maybe) throw a v-cmd locally
			// the hcmd comes from the PermissionProxy
			NameCertificate responseNameCertificate=null;
			OwnershipCertificate responseOwnershipCertificate=null;

			try {
				String cmdName = hcmd.getName();
				Object[] params = hcmd.getParams();

				if (cmdName.equals(PermissionSlice.NAMECERT_REQ)) {
					if ( params[0] instanceof String){
						// got a the name as string
						responseNameCertificate = 
							service.getNameCertificate( (String) params[0] );
					} else
						if ( params[0] instanceof JADEPrincipal){
							// got the sdisiname/pub.key as JADEPrincipal
							responseNameCertificate = 
								service.getNameCertificate( (JADEPrincipal) params[0] );
						}
				} // end NAMECERT_REQ


				if (cmdName.equals(PermissionSlice.OWNCERT_REQ)) {
					if ( (params[1]==null) && ( params[0] instanceof JADEPrincipal) ){
						// request of existing owned/owner
						responseOwnershipCertificate = 
							service.getOwnershipCertificate( (JADEPrincipal) params[0] );
					} else
						if ( (params[1]==null) && (params[0] instanceof String) ){
							// request of existing owned/owner
							responseOwnershipCertificate = 
								service.getOwnershipCertificate( (String) params[0] );
						} else 
							if ( (params[1]!=null) && (params[0] instanceof JADEPrincipal) && (params[1] instanceof JADEPrincipal) ){
								// creation of a new OwnershipCertificate
								responseOwnershipCertificate = 
									service.getOwnershipCertificate( (JADEPrincipal) params[0], (JADEPrincipal) params[1] );
							}
				} // end OWNCERT_REQ



			}
			catch (Throwable t) {
				hcmd.setReturnValue(t);
			}
			// the response containing (if found) the requested NameCertificate 
			if (responseNameCertificate!=null) {
				hcmd.setReturnValue(responseNameCertificate);
			} else 
				if (responseOwnershipCertificate!=null) {
					hcmd.setReturnValue( responseOwnershipCertificate );
				}

			// no vertical command issued
			return null;
		} // end serve(hcmd)

	} // end ServiceComponent




} // end class PermissionService
