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

import javax.security.auth.callback.*;
import javax.security.auth.login.*;

/**
 * Uses specified <code>CallBackHandler</code> to gather 
 * <code>userName</code> and <code>userPassword</code>
 * For use with remote containers where necessary to gather user/pass
 * information, but authenticate in Main container.
 *
 * @author Dominic Greenwood, Whitestein Technologies
 */
public class RemoteUserAuthenticator {

    // initial state
    private CallbackHandler callbackHandler;

    // user name and userPassword info 
    private String userName;
    private char[] userPassword;

    /**
     * Initialize this <code>RemoteUserAuthenticator</code>.
     *
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *			with the end user (garnering userNames and Passwords)
     *
     */
    public RemoteUserAuthenticator(CallbackHandler callbackHandler) {

	this.callbackHandler = callbackHandler;
    }

    /**
     * Gather User/Pass info using configured <code>CallBackHandler</code>.
     *
     * <p> The implementation of this method attempts to retrieve a 
     * <code>userName</code> and <code>userPassword</code>. 
     *
     * <p>
     *
     * @exception FailedLoginException if attempts to initiate the 
     *		callbackHandler fail.
     *
     */
    public void login() throws LoginException {

        if (callbackHandler==null) {
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
    }
    
}



 
 
 
  
