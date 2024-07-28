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

package jade.security;

import jade.core.Profile;
import jade.util.Logger;


/**
 * This is a factory class for security-related objects.
 *
 * @author Giosue Vitaglione - Telecom Italia LAB
 * @version $Date: 2005-03-02 16:53:14 +0100 (mer, 02 mar 2005) $ $Revision: 523 $
 */
abstract public class SecurityFactory {
  
  // NOTE: There can be more Profile (one for each container) into the same JVM
  // instead, there is one unique SecurityFactory into the whole JVM
// therefore, all containers into the same JVM must have the same security settings


  // this is the name of the parameter into the configuration file
  public static final String SECURITY_FACTORY_CLASS_KEY = "jade.security.SecurityFactory";
  public static final String SECURITY_FACTORY_CLASS_DEFAULT = "jade.security.impl.JADESecurityFactory";

  protected static Logger myLogger = Logger.getMyLogger(SecurityFactory.class.getName());


  // the singleton instance of this object
  private static SecurityFactory singleton = null;

  // the first profile registered with the SecurityFactory
  protected static Profile profile = null; // see NOTE above


  /*  Returns the SecurityFactory according the Profile p,
   *  The first time this is called, a single instance is created as
   *  a singleton.
   *  @seealso#getSecurityFactory()
   */
  static public SecurityFactory getSecurityFactory(Profile p) {
    String className = p.getParameter(SECURITY_FACTORY_CLASS_KEY,
                                      SECURITY_FACTORY_CLASS_DEFAULT);
    
    if (singleton == null) {

      try {
        singleton = (jade.security.SecurityFactory) Class.forName(className).
            newInstance();
      }
      catch (Exception e) {
        //e.printStackTrace();
        myLogger.log( Logger.SEVERE, "\nError loading jade.security SecurityFactory:"+className+"\nContinuing with default: " +SECURITY_FACTORY_CLASS_DEFAULT);
      }

      if (singleton == null) {
        try {
        myLogger.log( Logger.FINER, "Creating the SecurityFactory singleton"); 
          singleton = (jade.security.SecurityFactory) Class.forName(
              SECURITY_FACTORY_CLASS_DEFAULT).
              newInstance();
        myLogger.log( Logger.FINER, "SecurityFactory singleton created.");
        }
        catch (Exception e) {
          //e.printStackTrace();
          myLogger.log(Logger.SEVERE, "\nError loading SecurityFactory:" +
                         SECURITY_FACTORY_CLASS_DEFAULT);
          myLogger.log(Logger.SEVERE, " Exiting... ");
          System.exit( -1);
        }
      }
      profile = p;
    }
    return singleton;
  } // end getSecurityFactory


  /* Returns the SecurityFavtory if ever created.
   * If it has never created, returns 'null'.
   */
  static public SecurityFactory getSecurityFactory() {
    //System.out.println( "\n ---- getSecurityFactory()");
    return singleton;
  } // end getSecurityFactory






// methods to get configurations parameters value

public static String getParameter(String key, String defaultVal) {
    String val = null;
    if (profile!=null) {
      val = profile.getParameter( key, defaultVal);
    }
    return val;
} // end getProperty()



// abstract methods of the factory, follows:

 abstract public JADEAuthority newJADEAuthority();


//#ALL_EXCLUDE_BEGIN
  
    abstract public JADEAccessController newJADEAccessController(
    String name, JADEAuthority authority, String policy );
  
//#ALL_EXCLUDE_END


abstract public JADEPrincipal newJADEPrincipal(SDSIName sdsiname);
abstract public JADEPrincipal newJADEPrincipal(String string, SDSIName sdsiname1);

abstract public DelegationCertificate newDelegationCertificate();

} // end SecurityFactory
