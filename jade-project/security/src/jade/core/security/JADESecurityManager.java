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

package jade.core.security;


/**
   This replaces the standard Java security manager 
   in order to properly handle some special cases.

   @author Giosue Vitaglione - Telecom Italia LAB
   @version $Date: 2004-07-13 11:47:37 +0200 (mar, 13 lug 2004) $ $Revision: 394 $
*/
public class JADESecurityManager extends java.lang.SecurityManager {

  public void checkExit(int exitcode) throws SecurityException {
    //System.out.println("------------------ checkExit !!! ------------------");

    Class[] cl = this.getClassContext();
    //for (int i=0; i<cl.length; i++) System.out.println( cl[i].toString() );
    if (!(
    (cl[0].toString().equals("class jade.core.security.JADESecurityManager")) &&
    (cl[1].toString().equals("class java.lang.Runtime")) &&
    (cl[2].toString().equals("class java.lang.System")) &&
    (cl[3].toString().equals("class jade.core.Runtime$1")) &&
    (cl[4].toString().equals("class jade.core.Runtime$2")) &&
    (cl[5].toString().equals("class java.lang.Thread")) 
    ))
    {
    //System.out.println("------------------ System.exit() not allowed  ------------------");
      throw new SecurityException("Cannot call System.exit() from this point !");
      
    }
    super.checkExit(exitcode);
  }

} // end class JADESecurityManager
