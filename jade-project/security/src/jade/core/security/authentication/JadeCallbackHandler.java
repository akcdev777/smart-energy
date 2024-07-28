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

package jade.core.security.authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
*    Instantiation of a <code>CallbackHandler</code> to accept 
*    username and password from a <code>UserAuthenticator</code>. 
*    Intended for use when initiating Remote Containers.
*    This class is a simplified version of JadeDialogCallbackHandler 
*
*    @see javax.security.auth.callback
*    @author Dominic Greenwood - Whitestein Technologies AG 
*/
public class JadeCallbackHandler implements CallbackHandler {

    private String name = null;
    private char[] pass;

    private Component parentComponent;

    /**
     * Creates a callback handler using the passed attributes.
     *
     * @param userName the user 'name' identity component 
     * @param userPassword the user 'password' identity component
     */
    public JadeCallbackHandler( String userName, byte[] userPassword ) {
      this.name = userName; 
      pass = new char[userPassword.length];
      for (int i = 0; i < userPassword.length; i++) {
        this.pass[i] = (char)userPassword[i];
      } 
    }

    /**
     * Creates a callback handler and specifies a parent component.
     *
     * @param parentComponent the parent window - <code>null</code> for default 
     */
    public JadeCallbackHandler( Component parentComponent ) {
      this.parentComponent = parentComponent;
    }

    /*
     * An interface for recording actions to carry out if the user
     * clicks OK for the dialog.
     */
    private static interface Action {
	 void perform();
    }

    /**
     * Handles the specified set of callbacks.
     *
     * @param callbacks the callbacks to handle
     * @throws UnsupportedCallbackException if the callback is not an
     * instance  of NameCallback or PasswordCallback
     */

    public void handle(Callback[] callbacks)
	throws UnsupportedCallbackException
    {

	/* Collection actions to perform if the user clicks OK */
	final List okActions = new ArrayList(2);

	for (int i = 0; i < callbacks.length; i++) {
	    if (callbacks[i] instanceof TextOutputCallback) {
	    } else if (callbacks[i] instanceof NameCallback) {
 		final NameCallback nc = (NameCallback) callbacks[i];

		/* Store the name back into the callback if OK */
		okActions.add(new Action() {
		    public void perform() {
			nc.setName( name );
		    }
		});

 	    } else if (callbacks[i] instanceof PasswordCallback) {
 		final PasswordCallback pc = (PasswordCallback) callbacks[i];

		okActions.add(new Action() {
		    public void perform() {
			pc.setPassword( pass );
		    }
		});

	    } else if (callbacks[i] instanceof ConfirmationCallback) {
 	    } else {
 		throw new UnsupportedCallbackException(
		    callbacks[i], "Unrecognized Callback");
 	    }
	}

	Iterator iterator = okActions.iterator();
	while (iterator.hasNext()) {
          ((Action) iterator.next()).perform();
	}

    }

    /**
     * @return
     */
     public String getName() {
       return name;
     }

    /**
     * @return
     */
     public char[] getPasword() {
       return pass;
     }

    /**
     * @param n
     */
     public void setName(String n) {
       name = n;
     }

    /**
     * @param p
     */
     public void setPasword(char[] p) {
       pass = p;
     }

}     
