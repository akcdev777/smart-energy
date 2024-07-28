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

package jade.core.security.authentication;


import jade.util.Logger;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import jade.security.JADEPrincipal;
import jade.security.Credentials;
import jade.security.util.SecurityStore;
import jade.core.security.authentication.RemoteUserAuthenticator;
import jade.core.security.authentication.JadeTextCallbackHandler;
import jade.core.security.authentication.JadeDialogCallbackHandler;
import jade.core.security.authentication.JadeCallbackHandler;
import jade.security.JADESecurityException;

/**
 * @author Ivan Trencansky - Whitestein Technologies
 * @author Dominic Greenwood - Whitestein Technologies
 * @version  $Date: 2016-04-08 19:59:17 +0200 (ven, 08 apr 2016) $ $Revision: 2057 $
 */
public class UserAuthenticator {

	// principal and initial credentials for the logging user
	private static final String CMDLINE_HANDLER = "cmdline";
	private static final String DIALOG_HANDLER = "dialog";
	private static final String TEXT_HANDLER = "text";

	// principal and initial credentials for the logging user
	private JADEPrincipal principal = null;
	private Credentials creds = null;
	private String user = null;
	private byte[] pass = null;

	// instance callad-back that asks for user/passwd
	private JadeCallbackHandler jadeCallbackHandler = null;
	private JadeTextCallbackHandler jadeTextCallbackHandler = null;
	private JadeDialogCallbackHandler jadeDialogCallbackHandler = null;

	String authenticationContext = "";
	String authenticationCallback = "";
	String authenticationOwner = "";
	boolean remoteContainerLogin = false;

	private Logger myLogger = Logger.getMyLogger(this.getClass().getName());


	/**
	 * @param authenticationContext As contained into the JAAS login configuration file (E.g.: Kerberos, Windows, Unix, etc...)
	 */
	public UserAuthenticator(String authenticationContext, String authenticationCallback,
			String authenticationOwner, boolean remoteContainerLogin) {
		this.authenticationContext = authenticationContext;
		this.authenticationCallback = authenticationCallback.toLowerCase();
		this.authenticationOwner = authenticationOwner;
		this.remoteContainerLogin = remoteContainerLogin;
	}


	/**
	 * 
	 * @throws LoginException
	 */
	public void login() throws LoginException {

		//		setVmProperties();
		//		logVmProperties();

		if (authenticationCallback.equals(CMDLINE_HANDLER)) {
			if (authenticationOwner == null) throw new LoginException("CmdLine Login Callback requires the -owner parameter to be specified."); 
			else {
				String[] userpass = authenticationOwner.split(":");
				UserPassCredential userpassCredential = new UserPassCredential(userpass[0], userpass[1].getBytes());
				login(userpassCredential);           
			}
		} else if (authenticationCallback.equals(TEXT_HANDLER)) {
			textLogin();  
		} else if (authenticationCallback.equals(DIALOG_HANDLER)) {
			dialogLogin();  
		} 
	}

	/**
	 * Handle a login using known username and password Credentials  
	 * 
	 * @throws LoginException
	 * @throws SecurityException
	 */
	public void login(Credentials cred) throws LoginException, SecurityException {

		if (cred instanceof UserPassCredential)
		{
			// get user/pass
			String username = ((UserPassCredential)cred).getUsername();
			byte[] password = ((UserPassCredential)cred).getPassword();

			jadeCallbackHandler = new JadeCallbackHandler(username, password);

			// If remote container then just get user/pass withouti auth
			if (remoteContainerLogin) {
				RemoteUserAuthenticator remoteUserAuthenticator = new RemoteUserAuthenticator(jadeCallbackHandler);
				remoteUserAuthenticator.login();
			} else {

				LoginContext lc = null;

				try {
					lc = new LoginContext(authenticationContext, jadeCallbackHandler);
					myLogger.log( Logger.FINEST, 
							"UserAuthenticator -> Authentication Context is: "
									+ authenticationContext);
				} catch (LoginException le) {
					myLogger.log( Logger.SEVERE, 
							"UserAuthenticator -> Cannot create LoginContext. "
									+ le.getMessage());
					throw le;
				} catch (SecurityException se) {
					myLogger.log( Logger.SEVERE, 
							"UserAuthenticator -> Cannot create LoginContext. "
									+ se.getMessage());
					throw se;
				}

				// Try to authenticate.
				try {
					lc.login();
					myLogger.log(Logger.CONFIG, "UserAuthenticator -> Authentication succeeded!");
					// retrieve user's JADEPrincipal and initial Credentials
					user = jadeCallbackHandler.getName();
					pass = new String(jadeCallbackHandler.getPasword()).getBytes();
					getDataFromUserSecurityStore();
				} catch (LoginException le) {
					myLogger.log(Logger.SEVERE, 
							"UserAuthenticator -> Authentication has failed:\n"
									+ le.getMessage());
					throw le;
				}
			}
			// retrieve user's JADEPrincipal and initial Credentials
			user = jadeCallbackHandler.getName();
			pass = new String(jadeCallbackHandler.getPasword()).getBytes();
			getDataFromUserSecurityStore();
		} else {
			throw new LoginException("Credential type not supported: " + cred.getClass().getName() );
		}
	}


	/**
	 * Handle a login using a Swing dialog  
	 * 
	 * @throws LoginException
	 * @throws SecurityException
	 */
	private void dialogLogin() throws LoginException, SecurityException {

		jadeDialogCallbackHandler = new JadeDialogCallbackHandler();

		// If remote container then just get user/pass withouti auth
		if (remoteContainerLogin) {
			RemoteUserAuthenticator remoteUserAuthenticator = new RemoteUserAuthenticator(jadeDialogCallbackHandler);
			remoteUserAuthenticator.login();
		} else {

			int i;
			LoginContext lc = null;

			// Give user three attempts to authenticate.
			boolean loginDone = false;
			for (i = 0; i < 3; i++) {
				try {
					lc = new LoginContext(authenticationContext, jadeDialogCallbackHandler);
					myLogger.log(Logger.FINE, "UserAuthenticator -> Authentication Context is: "+ authenticationContext);
				} 
				catch (LoginException le) {
					myLogger.log(Logger.FINE, "UserAuthenticator -> Cannot create LoginContext. "+ le.getMessage());
					throw le;
				} 
				catch (SecurityException se) {
					myLogger.log(Logger.FINE, "UserAuthenticator -> Cannot create LoginContext. "+ se.getMessage());
					throw se;
				}

				// Try to authenticate.
				try {
					lc.login();
					// No exception == succesfull authentication.
					loginDone = true;
					break;
				} catch (LoginException le) {
					myLogger.log(Logger.WARNING, "UserAuthenticator -> Authentication failed:\n"+ le.getMessage());
				}
			}

			if (!loginDone) {
				// All three attempts to authenticate have failed.
				myLogger.log(Logger.SEVERE, "UserAuthenticator -> Three failure attempts to authenticate!!!");
				throw new LoginException("Three failure attempts to login.");
			} else {
				myLogger.log(Logger.FINE, "UserAuthenticator -> Authentication succeeded!");
			}
		}
		// retrieve user's JADEPrincipal and initial Credentials
		user = jadeDialogCallbackHandler.getName();
		pass = new String(jadeDialogCallbackHandler.getPasword()).getBytes();
		getDataFromUserSecurityStore();
	}

	/**
	 * Handle a login using a Text dialog  
	 * 
	 * @throws LoginException
	 * @throws SecurityException
	 */
	private void textLogin() throws LoginException, SecurityException {

		jadeTextCallbackHandler = new JadeTextCallbackHandler();

		// If remote container then just get user/pass withouti auth
		if (remoteContainerLogin) {
			RemoteUserAuthenticator remoteUserAuthenticator = new RemoteUserAuthenticator(jadeTextCallbackHandler);
			remoteUserAuthenticator.login();
		} else {

			int i;
			LoginContext lc = null;

			// Give user three attempts to authenticate.
			for (i = 0; i < 3; i++) {
				try {
					lc = new LoginContext(authenticationContext, jadeTextCallbackHandler);
					myLogger.log(Logger.FINE, 
							"UserAuthenticator -> Authentication Context is: "
									+ authenticationContext);
				} catch (LoginException le) {
					myLogger.log(Logger.SEVERE, 
							"UserAuthenticator -> Cannot create LoginContext. "
									+ le.getMessage());
					throw le;
				} catch (SecurityException se) {
					myLogger.log(Logger.SEVERE, 
							"UserAuthenticator -> Cannot create LoginContext. "
									+ se.getMessage());
					throw se;
				}

				// Try to authenticate
				try {
					lc.login();
					// No exception == succesfull authentication.
					break;
				} catch (LoginException le) {
					myLogger.log(Logger.SEVERE, 
							"UserAuthenticator -> Authentication has failed:\n"
									+ le.getMessage());
				}
			}

			if (i == 3) {
				// All three attempts to authenticate have failed.
				myLogger.log(Logger.SEVERE, 
						"UserAuthenticator -> Three failure attempts to authenticate!!!");

				throw new LoginException("Three failure attempts to login.");
			} else {
				myLogger.log(Logger.FINE, "UserAuthenticator -> Authentication succeeded!");
			}
		}
		// retrieve user's JADEPrincipal and initial Credentials
		user = jadeTextCallbackHandler.getName();
		pass = new String(jadeTextCallbackHandler.getPasword()).getBytes();
		getDataFromUserSecurityStore();
	}

	/**
	 * Extract credentials data from the user's Security Store  
	 * 
	 * @throws SecurityException
	 */
	private void getDataFromUserSecurityStore() throws SecurityException {

		myLogger.log(Logger.FINE, "Retrieving data from User Security Store...");
		// open the user's security store
		SecurityStore ss = new SecurityStore( user );
		//ss.open( passwd ); // TOFIX: this should throw SecurityException or other
		//          ss.open( "secret".getBytes() ); // TOFIX: real user password should be used (?)
		ss.open( pass ); 
		myLogger.log(Logger.FINER, " ss.hasMyKeyPair() = "+ss.hasMyKeyPair() );
		myLogger.log(Logger.FINER, " ss.getMyKeyPair() = "+ss.getMyKeyPair() );
		//Logger.println( " ss.getPrincipal(\"snoncemale\")=\n"+ss.getPrincipal("noncemale") );

		// retrieve principal and credentials
		principal = ss.getMyPrincipal();
		myLogger.log(Logger.FINE, " ss.getMyPrincipal()=\n"+ principal );
		creds = null; // TOFIX: Credentials storage not yet supported
	}

	public JADEPrincipal getPrincipal() {
		return principal;
	}
	public Credentials getCredentials() {
		return creds;
	}

	public String getUsername() {
		return user;
	}

	public byte[] getPassword() {
		return pass;
	}




	/**
	 * Optional setting of VM properties.
	 */
	 private void setVmProperties() {

		 System.setProperty(
				 "java.security.auth.login.config",
				 "/home/dgr/cvs/jade/add-ons/coresec/runExamples/SecurityHelper/jaas.conf");
		 System.setProperty("java.security.krb5.realm", "WHITESTEIN.COM");
		 System.setProperty("java.security.krb5.kdc", "WTAG40-WLAN.int.whitestein.ch");
		 //				System.setProperty("java.security.krb5.kdc", "library");
		 System.setProperty(
				 "java.security.krb5.conf",
				 "/etc/krb5.conf");
	 }

	 private void logVmProperties() {
		 Logger.println(
				 "logVmProperties() -> Config file: "
						 + System.getProperty("java.security.auth.login.config"));
		 Logger.println(
				 "logVmProperties() -> Default realm: "
						 + System.getProperty("java.security.krb5.realm"));
		 Logger.println(
				 "logVmProperties() -> Key Distribution Center: "
						 + System.getProperty("java.security.krb5.kdc"));
		 Logger.println(
				 "logVmProperties() -> javax.security.auth.login.name: "
						 + System.getProperty("javax.security.auth.login.name"));
	 }

}

