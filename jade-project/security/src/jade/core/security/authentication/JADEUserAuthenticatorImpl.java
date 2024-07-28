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

import jade.security.SecurityFactory;
import jade.security.Credentials;
import jade.security.JADEPrincipal;
import jade.core.security.authentication.JADEUserAuthenticator;
import jade.core.security.authentication.UserPassCredential;

import java.util.Vector;
import java.io.BufferedReader;
import java.io.FileReader;
import jade.util.Logger;
import jade.security.util.Digest;
import javax.security.auth.login.LoginException;


/**
*    <code>JADEUserAuthenticatorImpl</code> is the
*    entity that takes as input a couple: username/password
*    and provides:
*       - the JADEPrincipal associated (if present, also with SDSIName)
*       - and Credentials (if any) owned by that user at start-up time.
*
*
*    @author Giosue Vitaglione - Telecom Italia LAB
*    @version $Date: 2004-07-31 14:53:18 +0200 (sab, 31 lug 2004) $ $Revision: 487 $
*/
public class JADEUserAuthenticatorImpl implements JADEUserAuthenticator {


  public static final String PWD_HASH_ALGORITHM_KEY = "jade_security_impl_pwdHashAlgorithm";
  public static final String PWD_HASH_ALGORITHM_DEFAULT =  "DES";


// this object represent a login contaxt;
// once login() is sucessufly called, 
// the following variables are available through this object: 
private JADEPrincipal principal=null;
private Credentials creds = null;



  public void login() throws LoginException, SecurityException {
    
  }
  
  /**
   *
   */
  public void login(Credentials cred) throws LoginException, SecurityException {
    if (cred instanceof UserPassCredential)
    {
      // get user/pass
      String username = ((UserPassCredential)cred).getUsername();
      byte[] password = ((UserPassCredential)cred).getPassword();

      // go through user list
      // check that user is present and password is valid
      boolean ok = checkUser( username, password);
      if (!ok) throw new LoginException("User authentication error. (user="+username+")");

      // here: the user/pass were ok.

      // locate the SecurityStore of 'user'
      // get the principal
      // get his start-up credentials


    } else {
      throw new LoginException("Credential type not supported: " + cred.getClass().getName() );
    }
  } // end login()

  public JADEPrincipal getPrincipal() {
    return principal;
  }

  public Credentials getCredentials() {
    return creds;
  }



// private methods follow

private Vector users = null;

private boolean checkUser(String name, byte[] password) throws LoginException {
    
    boolean retVal = false;
    // get security factory (for getting configuration parameters)
    SecurityFactory sf = SecurityFactory.getSecurityFactory();
    if (sf!=null) {
 
      // what algorithm (and password file format) should I use?
      String digest_alg = SecurityFactory.getParameter(
                   PWD_HASH_ALGORITHM_KEY, 
                   PWD_HASH_ALGORITHM_DEFAULT);
      
      if (digest_alg.compareTo("DES") == 0) {
        try {
          retVal = checkUser_DES(new UserPassCredential(name, password));
        } catch (LoginException e) { throw e;}
      }
      else {
        // other digest algorithms (es. MD5, MD2, SHA-1)
//          hash = Digest.digest(password, digest_alg);
      }
      
    } else {
      // SecurityFactory sf is null, (even not dummy) this is a problem, cannot authenticate
      retVal = false;
      throw new LoginException("Authentication error. Could not retrieve SecurityFactory. Check your configuration.");
    }

    return retVal; //  user/pasword correct ?
} 


// go through the password file and check the provided user/pass
private boolean checkUser_DES(UserPassCredential cred) throws LoginException {
    boolean retVal = false;
    String user = null;
    String pass = null;

// --- load and parse password file ---
  String passwdFile = null;
  SecurityFactory sf = SecurityFactory.getSecurityFactory();
  passwdFile = SecurityFactory.getParameter(
        jade.core.security.authentication.SimpleLoginModule.AUTHENTICATION_LOGINSIMPLECREDFILE_KEY,
        jade.core.security.authentication.SimpleLoginModule.AUTHENTICATION_LOGINSIMPLECREDFILE_DEFAULT);

  //Logger.println("parsing passwd file " + passwdFile);
  if (passwdFile == null) {
    throw new LoginException("Password file not found: "+passwdFile);
  }

  // parse the password file, line by line
  try {
    BufferedReader file = new BufferedReader(new FileReader(passwdFile));
    String line = file.readLine();
    while (line != null) {
      line = line.trim();
      if (line.length() > 0) {
        int sep = line.indexOf(':');
        int sep2 = line.indexOf(':', sep + 1);
        //System.out.println(sep +" , "+ sep2);
        //System.out.println( line );
        // The password can be after a ":"
        // or in between two ":"
        if (sep != -1) {
          user = line.substring(0, sep);
          if (sep2 != -1) {
            pass = line.substring(sep + 1, sep2);
          }
          else {
            pass = line.substring(sep + 1, line.length());
          }
        }
        else {
          user = line;
          pass = null;
        }
        //Logger.println("username=" + user + "; password=" + pass );

        // check if this is the user
        if (user.compareTo(cred.getUsername()) != 0) {
          // no, it isn't, go to the next line
        }
        else {
          // yes, this is the user. Check the password: 

          // Calculate hash of provided password
          // using the Digest Algorithm choosen in the Jade profile
          String hash = "";

          // here 'pass' contains the hashed password as it is stored 
          // in the password file

          // first two password chars is the salt
          String salt = pass.substring(0, 2);

          // create the hash of the provided password
          hash = Digest.digest(cred.getPassword(), "DES", salt);

          //Logger.println("     hash="+hash);
          //Logger.println("     pass="+pass+ "\n");
        
          // Compare the hash of provided password
          // to the entry in the password file
          if (pass.compareTo(hash)==0){
            // ok: user found + exact password
            retVal = true;
            break; //exit from the loop, and do not read further lines.
          } else {
            Logger.println("\n\n WRONG PASSWORD : " + hash + " <> " + pass);
            //--> throw new AuthenticationException("Wrong password");
            retVal = false;
          }

        } // end if

      } // enf if line.length>0

      // read next line
      line = file.readLine();

    } // end while
  } catch (Exception e) {
    e.printStackTrace();
  }

  return retVal;
} // end checkUser_DES

} // end JADEUserAuthenticatorImpl
