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

package jade.security.impl;

import jade.security.JADEPrincipal;
import jade.security.JADEAuthority;
import jade.security.JADECertificate;
import jade.security.PrivilegedExceptionAction;
import jade.security.CertificateException;
import jade.security.DelegationCertificate;
import java.security.Permission;
import java.security.Permissions;
import java.security.Policy;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;
import java.security.AccessController;
import java.security.AccessControlContext;
import java.security.CodeSource;
import java.security.PrivilegedActionException;
import java.security.DomainCombiner;
import jade.security.Credentials;
import jade.security.JADESecurityException;
import jade.security.util.SecurityStore;
import jade.core.security.authentication.NameCertificate;
import jade.core.security.authentication.OwnershipCertificate;
import java.util.Enumeration;
import java.util.Vector;
import jade.util.Logger;
import jade.security.Name;


/**
    The <code>JADEAccessControllerImpl</code>
    is an implementation class.
    Look at the documentation of the related interface.
 @author Giosue Vitaglione - Telecom Italia LAB
 @version $Date: 2016-04-14 08:39:47 +0200 (gio, 14 apr 2016) $ $Revision: 2061 $
 */
public class JADEAccessControllerImpl implements jade.security.JADEAccessController {

	private String ac_name = null;
	private JADEAuthority authority = null;

	// The securitystore used
	private SecurityStore securityStore = null;

	Logger myLogger = myLogger = Logger.getMyLogger(this.getClass().getName());

	// constructor
	public JADEAccessControllerImpl(String name, JADEAuthority authority, String policy) {
		this.ac_name = name;
		this.authority = authority;
//		setPolicy( policy );
		initSecurityStore();
	}

//	private void setPolicy(String policyFile) {
//		try {
//			//if (System.getSecurityManager() == null) {
//			System.setProperty("java.security.policy", policyFile);
//			myLogger.log( Logger.CONFIG, "Setting security policy: "+policyFile);
//			//Policy.getPolicy();
//			//Policy.setPolicy(new sun.security.provider.PolicyFile());
//			//System.out.println("Setting security manager");
//			//System.setSecurityManager(new SecurityManager());
//			//}
//		}
//		catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
	
	private void initSecurityStore() {
		// Locally (into the securityStore) we have a table that maps:
		// JADEPrincipal => localAlias[]
		securityStore = new SecurityStore( ac_name );
		securityStore.open("secret".getBytes());
		securityStore.flush();
	}


	/**
	 */
	public synchronized void checkAction(JADEPrincipal requester,
	                                     Permission permission,
	                                     JADEPrincipal target,
	                                     Credentials credentials) throws JADESecurityException {

		if (requester==null) {
			// 'null' is not a valid requester. Set the default "guest" requester
			requester=new JADEPrincipalImpl("guest");
		}

		// local names of the requester that are accredited of performing the requested action
		Vector localNames = new Vector();

		// --- retrieve the entry from the table JADEPrincipal -> Alias
		Name[] requesterLocNames = securityStore.getLocalNames( requester );

		// typically the requester has one local name only
		if (requesterLocNames!=null) myLogger.log(Logger.FINE, "Retrieved requester's Local alias, is: '"+ requesterLocNames[0] +"'");

		if ( (requesterLocNames==null) || (requesterLocNames.length<1) || (requesterLocNames[0].getName()==null)) { 
			// a local name is not known.
			// try to retrieve a NameCertificate from a NameAuthority
			NameCertificate nc=null;
			if (nameAuthority!=null) {
				nc = nameAuthority.getNameCertificate(requester);
			}
			if (nc!=null) {
				// TOFIX: certificate should be verified
				String certifiedName = nc.getSubject().getName();
				if (certifiedName!=null) 
					requesterLocNames = Name.getName( new String[] {certifiedName});
			}
		}
		if (requesterLocNames!=null) {
			for (int i=0; i<requesterLocNames.length; i++) {
				if ( requesterLocNames[i] != null) {
					if (requesterLocNames[i].getName()!=null)
						localNames.add( (Name) requesterLocNames[i] );       
				}
			}
		}



		// "unroll" the credentials
		// from the given credentials, check if there are delegationcertificate or 
		// OwnershipCertificate that extend the requester capabilities
		if (credentials!=null) {
			Enumeration creds = credentials.elements();
			while (creds.hasMoreElements()){
				Object cred = creds.nextElement();
				if (cred instanceof OwnershipCertificate){
					// TOFIX: verify certificate
					JADEPrincipal owner = ((OwnershipCertificate)cred).getOwner();
					if (owner!=null) {
						// add the name of the owner
						localNames.add( new Name(owner.getName()) );
						// add (if any) other local aliases of the owner principal 
						Name[] ownerNames = securityStore.getLocalNames( owner );
						if ((ownerNames!=null) && (ownerNames[0]!=null)) 
							localNames.add( ownerNames[0] ); // assume single owner alias
					}
				} 
				else if (cred instanceof DelegationCertificate){
					// verifies the cert
					// extract the additional local names 
					// taking into account: both 'permission' and certificates
				} 
			}
		}


		// TOFIX: temporary hack (users are not present yet into ac-jade store)
		if ( (localNames.size()<1) || (((Name)localNames.get(0)).getName()==null) ){ 
			Name user=new Name(requester.getName());
			localNames.add( user );
			myLogger.log(Logger.FINER, "### Requester's Local name converted to: '"+ user.getName() +"'");
		}


		// the special LocalName '*' can be played by everybody
		localNames.add( new Name("*") );


		// convert the localNames Vector to an array
		Name[] locNames = new Name[ localNames.size() ];
		for (int i=0; i<localNames.size(); i++) 
			locNames[i]= (Name) localNames.get(i);

		// Construct a ProtectionDomain from the LocalNames
		Policy ac_policy = Policy.getPolicy();
		CodeSource source = new CodeSource(null, (java.security.cert.Certificate[]) null);
		ProtectionDomain lnpd = new ProtectionDomain(source, null, getClass().getClassLoader(), locNames);
		// Check the permission
		PermissionCollection perms = ac_policy.getPermissions( lnpd );
		boolean passed = perms.implies( permission );

		if (!passed) { 
			StringBuffer str = new StringBuffer();
			str.append( "Permission check FAILED: Requester="+requester.getName()+", local-names={");
			for (int i=0; i<locNames.length;i++) {
				str.append( locNames[i] +" ");
			}
			str.append("}, associated-permissions="+perms); 
			str.append(", policy file="+System.getProperty(jade.core.security.permission.PermissionService.POLICY_FILE_KEY));
			str.append(", required-permission="+permission);
			str.append(", Policy="+ac_policy+" of class "+ac_policy.getClass().getName());
			myLogger.log(Logger.WARNING, str.toString());
			
			throw new JADESecurityException("AccCtrl "+ac_name+
					", req from:"+requester.getName()+
					", -Not Authorized- "+permission
					);
		}
	} // end checkAction()





	public Object doPrivileged(PrivilegedExceptionAction action) throws Exception {
		throw new Exception("JADEAccessControllerImpl:  doPrivileged() method not implemented yet.");
		//    return new Object();
	}


	// this private class is needed to properly intersect the protection domains
	// of JADE (AllPermission) and the agent's code
	private class MyDomainCombiner
	implements DomainCombiner {
		public ProtectionDomain[] combine(ProtectionDomain[] currentDomains,
				ProtectionDomain[] assignedDomains) {
			return assignedDomains;
		} // end combine
	} // end class



	/**
	 * Make a priviledged action by using the given credentials
	 *
	 * @param action
	 * @param certs
	 * @return
	 * @throws java.lang.Exception
	 */
	public Object doAsPrivileged(PrivilegedExceptionAction action,
			final Credentials credential) throws Exception {


		// --- create the context where the action will be executed ---
		AccessControlContext acc = (AccessControlContext) AccessController.
				doPrivileged(
						// begin AccessController.doPrivileged call
						new java.security.PrivilegedExceptionAction() {
							public Object run() throws Exception {

								verifySubject(credential);
								ProtectionDomain domain = new ProtectionDomain(
										new CodeSource(null, (java.security.cert.Certificate[])null), collectPermissions(credential), null, null);

								MyDomainCombiner myDomainCombiner = new MyDomainCombiner();

								AccessControlContext acc = new AccessControlContext(
										new AccessControlContext(
												new ProtectionDomain[] {domain}
												),
												myDomainCombiner
										);
								return acc;
							}
						}); // end AccessController.doPrivileged call


		// --- execute the action in the proper context ---
		try {
			return AccessController.doPrivileged(action, acc);
		}
		catch (PrivilegedActionException e) {
			throw e.getException();
		}

	} // end doAsPrivileged() method



	private void verifySubject(Credentials creds) throws
	JADESecurityException {
		/*
    if (certs.getIdentityCertificate() == null) {
      throw new JADESecurityException("Null identity");
    }

    verify(certs.getIdentityCertificate());
    for (int d = 0;
         d < certs.getDelegationCertificates().size() &&
         certs.getDelegationCertificates().get(d) != null; d++) {
      if (! ( (JADEPrincipalImpl) certs.getIdentityCertificate().getSubject()).
          implies( (JADEPrincipalImpl) ( (DelegationCertificate) certs.
                                    getDelegationCertificates().get(d)).
                  getSubject())) {
        throw new JADESecurityException(
            "Delegation-subject doesn't match identity-subject");
      }
      verify( (DelegationCertificate) certs.getDelegationCertificates().get(d));
    }
		 */
	}



	private PermissionCollection collectPermissions(Credentials creds) {
		Permissions perms = new Permissions();
		/*
    for (int j = 0;
         j < certs.getDelegationCertificates().size() &&
         certs.getDelegationCertificates().get(j) != null; j++) {
      for (Iterator i = ( (DelegationCertificate) certs.
                         getDelegationCertificates().get(j)).getPermissions().
           iterator(); i.hasNext(); ) {
        Permission p = (Permission) i.next();
        perms.add(p);
      }
    }
		 */
		return perms;
	}

	private static void verify(JADECertificate certificate) throws JADESecurityException {
		/*        if (publicKey == null)
                    return;
            if (certificate == null)
                    throw new JADESecurityException("Null certificate");
            if (! (certificate instanceof BasicCertificateImpl))
                    throw new JADESecurityException("Unknown certificate class");
            try {
         byte[] signBytes = ((BasicCertificateImpl)certificate).getSignature();
                    // We have to delete signature, first
                    ((BasicCertificateImpl)certificate).setSignature(null);
                    byte[] certBytes = certificate.getEncoded();
                    // Now we can put signature back in its place
         ((BasicCertificateImpl)certificate).setSignature(signBytes);
                    if (signBytes == null)
                            throw new JADESecurityException("Null signature");
                    Signature sign = Signature.getInstance("DSA");
                    sign.initVerify(publicKey);
                    sign.update(certBytes);
                    if (! sign.verify(signBytes))
                            throw new JADESecurityException("Corrupted certificate");
            }
            catch (CertificateEncodingException e1) {
                    e1.printStackTrace();
            }
            catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
            }
            catch (InvalidKeyException e2) {
                    e2.printStackTrace();
            }
            catch (SignatureException e3) {
                    throw new JADESecurityException(e3.getMessage());
            }
            catch (ClassCastException e4) {
                    throw new JADESecurityException(e4.getMessage());
            }
		 */
	}



	/**
	 * (optionally) it can be associated a NameAuthority, so that 
	 *  when a principal does not have a known local alias, 
	 *  a NameCertificate is retrieved. The local alias used 
	 *  is the name contained into the certificate.
	 */
	public void setNameAuthority(NameAuthority nameAuthority){
		this.nameAuthority=nameAuthority;
	}
	private NameAuthority nameAuthority = null;

}
