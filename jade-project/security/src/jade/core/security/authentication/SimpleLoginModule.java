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

package jade.core.security.authentication;

import jade.core.security.authentication.SimplePrincipal;
import java.util.*;
import java.io.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.spi.*;

/**
 * <p> This <code>LoginModule</code> imports a simple <code>userName</code>
 * and <code>userPassword</code> 
 * and associates them with the current <code>Subject</code>.
 *
 * <p> This LoginModule recognizes the debug option.
 * If set to true in the login Configuration,
 * debug messages will be output to the output stream, System.out.
 *
 * @version 1.0, 08/04/04
 * @author Dominic Greenwood, Whitestein Technologies
 */
public class SimpleLoginModule implements LoginModule {

    public static final String AUTHENTICATION_LOGINSIMPLECREDFILE_KEY = 
        "jade_security_authentication_loginsimplecredfile";
    public static final String AUTHENTICATION_LOGINSIMPLECREDFILE_DEFAULT = 
        "passwords.txt";

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    // configurable option
    private boolean debug = true;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    // user name and userPassword info 
    private String userName;
    private char[] userPassword;
    private String credsFile;
    private SimplePrincipal userPrincipal;
//    public abstract boolean verifyPasswd(String log, char[] pass, String f);

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * <p>
     *
     
     *
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *			with the end user (prompting for userNames and
     *			userPasswords, for example). <p>
     *
     * @param sharedState shared <code>LoginModule</code> state. <p>
     *
     * @param options options specified in the login
     *			<code>Configuration</code> for this particular
     *			<code>LoginModule</code>.
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map sharedState, Map options) {

	this.subject = subject;
	this.callbackHandler = callbackHandler;
	this.sharedState = sharedState;
	this.options = options;

	// initialize any configured options
	debug = "true".equalsIgnoreCase((String)options.get("debug"));
        credsFile = System.getProperty(AUTHENTICATION_LOGINSIMPLECREDFILE_KEY, 
                                       AUTHENTICATION_LOGINSIMPLECREDFILE_DEFAULT);
    }

    /**
     * Authenticate the user (first phase).
     *
     * <p> The implementation of this method attempts to retrieve a 
     * <code>userName</code> and <code>userPassword</code>. 
     *
     * <p>
     *
     * @exception FailedLoginException if attempts to initiate the 
     *		callbackHandler fail.
     *
     * @return true in all cases (this <code>LoginModule</code>
     *		should not be ignored).
     */
    public boolean login() throws LoginException {

        if (callbackHandler==null) {
            succeeded = false;
            throw new FailedLoginException
                    ("Error: no CallbackHandler available.");
        }

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("Username: ");
        callbacks[1] = new PasswordCallback("Password: ", false);

        try {
            callbackHandler.handle(callbacks);
            userName = ((NameCallback)callbacks[0]).getName();
            char[] tmpuserPassword = ((PasswordCallback)callbacks[1]).getPassword();
            if (tmpuserPassword==null) {
                userPassword = new char[0];
            } else {
                userPassword = new char[tmpuserPassword.length];
                System.arraycopy(tmpuserPassword,0, userPassword,0,tmpuserPassword.length);
            }

            ((PasswordCallback)callbacks[1]).clearPassword();
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("Error: no authentication");
        }

        if (debug) {
            System.err.println("Username: " + userName);
            System.err.println("Password: " + userPassword);
        }

        succeeded = verifyLogin(userName,userPassword,credsFile);

        if (succeeded) {
            if (debug) System.out.println("\t\t[SimpleLoginModule]: " +
                    "Authentication succeeded");
            return true;
        } else { 
            if (debug) System.out.println("\t\t[SimpleLoginModule]: " +
                    "Authentication failed");
            userName = null;
            userPassword = null;
            throw new FailedLoginException("Login failed");
        }
    }
    
    /**
     * Commit the authentication (second phase).
     *
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * succeeded).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded, then this method associates the collect information
     * with the <code>Subject</code> currently tied to the 
     * <code>LoginModule</code>.  If this LoginModule's
     * authentication attempted failed, then this method removes
     * any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the commit fails
     *
     * @return true if this LoginModule's own login and commit attempts
     *		succeeded, or false otherwise.
     */
    public boolean commit() throws LoginException {
        if (!succeeded) return false;

	if (subject.isReadOnly()) {
            throw new LoginException 
                  ("Commit Failed: Subject is Readonly");
	}

        userPrincipal = new SimplePrincipal(userName);

        if (!subject.getPrincipals().contains(userPrincipal))
            subject.getPrincipals().add(userPrincipal);

        if (debug) {
		System.out.println("\t\t[SimpleLoginModule]: " +
                    "Added SimplePrincipal to Subject");
        }

        userName = null;
        userPassword = null;
        commitSucceeded = true;
        return true;
    }
     
    /**
     * Abort the authentication (second phase).
     *
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * did not succeed).
     *
     * <p> This method cleans up any state that was originally saved
     * as part of the authentication attempt from the <code>login</code>
     * and <code>commit</code> methods.
     *
     * <p>
     *
     * @exception LoginException if the abort fails
     *
     * @return false if this LoginModule's own login and/or commit attempts
     *		failed, and true otherwise.
     */
     
    public boolean abort() throws LoginException {
	if (debug) {
	    System.out.println("\t\t[SimpleLoginModule]: " +
		"aborted authentication attempt");
	}

	if (succeeded == false) {
	    return false;
	} else if (succeeded == true && commitSucceeded == false) {
	    succeeded = false;
	    userName = null;
	    userPassword = null;
	    userPrincipal = null;
	} else {
	    logout();
	}
	return true;
    }

    /**
     * Logout the user
     *
     * <p> This method removes the Principals associated
     * with the <code>Subject</code>.
     *
     * <p>
     *
     * @exception LoginException if the logout fails
     *
     * @return true in all cases (this <code>LoginModule</code>
     *		should not be ignored).
     */
     
    public boolean logout() throws LoginException {

	if (subject.isReadOnly()) {
		throw new LoginException 
		    ("logout Failed: Subject is Readonly");
	    }

	subject.getPrincipals().remove(userPrincipal);

	succeeded = false;
	commitSucceeded = false;
	userPrincipal = null;
	userName = null;
	userPassword = null;

	if (debug) {
	    System.out.println("\t\t[SimpleLoginModule]: " +
		"logged out Subject");
	}
	return true;
    }

    /**
     * Verify the Login credentials
     *
     * <p> This method verifies the simple login credentials
     * against the credentials stored in SimpleLoginCredentials
     *
     * <p>
     *
     * @exception LoginException if the verification fails
     *
     * @return true if the verification succeeds, otherwise false.
     */

    private boolean verifyLogin(String userName, char[] userPassword, String loginCreds) throws LoginException {

        File file = new File(loginCreds);

        try {
            InputStream is = new FileInputStream(file);

            String pass = new String(userPassword);
            Properties pwdfile = new Properties();
            pwdfile.load(is);
            String pswd = pwdfile.getProperty(userName);

            if (pwdfile.getProperty(userName.trim(),"username").trim().equals(pass.trim())) {
              System.out.println("User '"+userName+"' Successfully Authenticated.\n");
              is.close();
              return true;
            } 
            is.close();
            return false;
        } catch (java.io.IOException ioe) {
            if (!file.exists()) {
                if (loginCreds.equals(AUTHENTICATION_LOGINSIMPLECREDFILE_DEFAULT)) {
                    throw new LoginException("Cannot locate default password file: " + loginCreds);
                } else {
                    throw new LoginException("Cannot locate specified password file: " + loginCreds);
                }
            } else {
                throw new LoginException(ioe.toString());
            }
        } 
    }
}



 
 
 
  
