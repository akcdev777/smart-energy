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

import jade.core.AgentContainer;
import jade.core.Filter;
import jade.core.Profile;
import jade.core.Service;
import jade.core.VerticalCommand;
import jade.core.management.AgentManagementSlice;
import jade.core.messaging.MessagingSlice;
import jade.core.security.permission.checkers.MessagingChecker;
import jade.core.security.permission.checkers.SimpleJADEChecker;
import jade.security.impl.JADEAccessControllerImpl;
import jade.util.Logger;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import jade.security.JADESecurityException;




/**

   This is the filter used into the PermissionService.

   @author Giosue Vitaglione - Telecom Italia LAB
   @author Jerome Picault - Motorola Labs

   @see jade.core.security.permission.PermissionService
*/
public class PermissionFilter extends Filter {


    private static final String CHECKERTABLE_FILLER_CLASS_KEY="jade_security_permission_CheckerTableFiller";
  
    public PermissionFilter() {
    }
    
    private static Logger myLogger = Logger.getMyLogger( PermissionFilter.class.getName() );

    protected PermissionService service;
    protected AgentContainer myContainer;
    protected Profile myProfile;
    protected boolean direction;

    // this table contains the mapping:
    // (cmd name) <-> (checkers)
    public CheckerTable checkerTable = new CheckerTable();


    // init the PermissionFilter
    public void init( PermissionService service, AgentContainer myContainer, Profile myProfile, boolean direction ){
      this.service = service;
      this.myContainer = myContainer;
      this.myProfile = myProfile;
      setPreferredPosition( 5 );  // Soon, but not necessarily the first
      this.direction=direction;

      // Load rows into the checkerTable 
      String fillerClass = myProfile.getParameter(CHECKERTABLE_FILLER_CLASS_KEY, null);
      if (fillerClass!=null) {
        CheckerTableFiller ctFiller;
        try {
          ctFiller = (CheckerTableFiller) Class.forName(fillerClass).newInstance();
          // Load rows into the checkerTable by using a custom CheckerTableFiller
          ctFiller.fillChecherTable( this );
          myLogger.log( Logger.FINE, "CheckerTable filled by:"+fillerClass );
        }
        catch (Exception ex) {
          //#PJAVA_EXCLUDE_BEGIN
          myLogger.log( Logger.SEVERE, "Could not load custom CheckerTableFiller: '"+ fillerClass +
                        "'. Please check config param: "+CHECKERTABLE_FILLER_CLASS_KEY+"", ex);
          //#PJAVA_EXCLUDE_END
          /*#PJAVA_INCLUDE_BEGIN
          myLogger.log( Logger.SEVERE, "Could not load custom CheckerTableFiller: '"+ fillerClass +
                        "'. Please check config param: "+CHECKERTABLE_FILLER_CLASS_KEY+"");
          #PJAVA_INCLUDE_END*/ 

        }
      } else {
        // Load rows into the checkerTable by using the default code-wired.
        fillCheckerTable();
        myLogger.log( Logger.FINE, "CheckerTable filled by (as default) PermssionFilter.");
      }
    } // end init()


    public boolean getDirection() { return direction; }
    public String getNodeName() { return myContainer.getID().getName(); }
    

    /**
     *    Load rows into the checkerTable.
     */
    protected void fillCheckerTable() {
      SimpleJADEChecker.setDefaultProfile( myProfile );
      SimpleJADEChecker.setDefaultJADEAccessController( service.getJADEAccessController() );
      SimpleJADEChecker.setDefaultContainer( myContainer );
      SimpleJADEChecker.setDefaultPermissionService( service );


      // load (SOME) rows into the checkerTable 
      // this will be implemented differently (each servise registers its rows in this table)

      /*
      // --- AgentMobilty ---
      checkerTable.add( AgentMobilityHelper.INFORM_CLONED, 
                        new MobilityChecker() );
      checkerTable.add( AgentMobilityHelper.INFORM_MOVED, 
                        new MobilityChecker() );
      checkerTable.add( AgentMobilityHelper.REQUEST_CLONE, 
                        new MobilityChecker() );
      checkerTable.add( AgentMobilityHelper.REQUEST_MOVE, 
                        new MobilityChecker() );
      */


      // --- Messaging ---
      MessagingChecker m_checker = new MessagingChecker();
      m_checker.setDirection(direction);
      checkerTable.add( MessagingSlice.SEND_MESSAGE,
                        m_checker ); 
      checkerTable.add( MessagingSlice.DEAD_MTP,
                        m_checker ); 
      checkerTable.add( MessagingSlice.INSTALL_MTP,
                        m_checker ); 
      checkerTable.add( MessagingSlice.NEW_MTP,
                        m_checker ); 
      checkerTable.add( MessagingSlice.NOTIFY_FAILURE,
                        m_checker ); 
      checkerTable.add( MessagingSlice.SET_PLATFORM_ADDRESSES,
                        m_checker ); 
      checkerTable.add( MessagingSlice.UNINSTALL_MTP, 
                        m_checker ); 



      // --- AgentManagement ---
      SimpleJADEChecker am_checker = new SimpleJADEChecker();
      am_checker.setDirection(direction);
      checkerTable.add( AgentManagementSlice.ADD_TOOL,
                        am_checker );

      checkerTable.add( AgentManagementSlice.INFORM_CREATED,
                        am_checker );
      checkerTable.add( AgentManagementSlice.INFORM_KILLED, 
                        am_checker );
      checkerTable.add( AgentManagementSlice.INFORM_STATE_CHANGED, 
                        am_checker );

      checkerTable.add( AgentManagementSlice.SHUTDOWN_PLATFORM, am_checker );
      checkerTable.add( AgentManagementSlice.KILL_CONTAINER, am_checker );
      checkerTable.add( AgentManagementSlice.REMOVE_TOOL, am_checker );

      checkerTable.add( AgentManagementSlice.REQUEST_CREATE,
                        am_checker );
      checkerTable.add( AgentManagementSlice.REQUEST_KILL, 
                        am_checker );
      checkerTable.add( AgentManagementSlice.REQUEST_STATE_CHANGE, 
                        am_checker );

      checkerTable.add( Service.NEW_NODE,
                        am_checker );



      // possible way to load the checherTable: 
      // load from the directory CMD_CHECKER
      // the files containing the mappings
      // all *.conf files contained into this dir are read
      // (usually one file for each service, but it is not a limitation)
      // file names are not important nor used
      //  --- Format of a file: property file like:
      // INSTALL_MTP="jade.security.permission.checkers.MtpChecker"
      // UNINSTALL_MTP="jade.security.permission.checkers.MtpChecker"
      // ...format to be discussed...


    } // end fillCheckerTable()






    /**
       Perform the authorization check on the received command.

    */
    public boolean accept(VerticalCommand cmd) {
     if (cmd==null) return true; // null cmd are allowed to pass 

      //log(direction, cmd);
      
      String name = cmd.getName();


      /*
       - whose this cmd is it?
       - are there credentials attached to this cmd ?
       - which command is this?
       - entry in table: (cmd-type, cmd-checker), get the checker(s)
       - for each checker:
           - invoke the check method
      */


      try {
        // look for checkers that handle command name, and
        // call the check methods on the command
        Vector checkers = checkerTable.get( name );
        if (checkers!=null) {
          for (Enumeration e = checkers.elements(); e.hasMoreElements(); ) {
            ( (CommandChecker) e.nextElement()).check(cmd);
          }
        }
      } catch (JADESecurityException e) {


        if (e.getMessage().equals("vetoed")) {
            // cmd already contains the right return value
        } else {
          // authorization exception, something was not authorized
          if (myLogger.isLoggable(Logger.SEVERE))
          myLogger.log(Logger.SEVERE, 
                     ((direction==Filter.INCOMING) ? " UP " : "down")+
                     "[PermissionFilter] NOT AUTHORIZED!!!\n" + e.getMessage() ); 
          //e.printStackTrace();

          // this is passed back to who created the vertical command
          cmd.setReturnValue( e );
        }

        // if it returns 'false' the cmd gets stopped
        // either because it is not authorized or
        // it has been vetoed
        return false;

      } catch (Throwable e) {
          //#PJAVA_EXCLUDE_BEGIN
          myLogger.log(Logger.WARNING, "[PermissionFilter] Unexpected error checking permissions for V-Command "+cmd.getName()+" of Service "+cmd.getService(), e); 
          //#PJAVA_EXCLUDE_END
          /*#PJAVA_INCLUDE_BEGIN
          myLogger.log(Logger.SEVERE, "[PermissionFilter] "); 
          #PJAVA_INCLUDE_END*/ 
      }

      // No JADESecurityException was thrown, so it is passed.
      // 'true' means the cmd is authorized
      return true;
    } // end accept mehotd


//#PJAVA_EXCLUDE_BEGIN
static java.util.logging.Level LEV = Logger.FINE;
//#PJAVA_EXCLUDE_END
/*#PJAVA_INCLUDE_BEGIN
static int LEV = Logger.FINE;
#PJAVA_INCLUDE_END*/ 
public static synchronized void log(boolean direction, jade.core.Command cmd) {
      if (!myLogger.isLoggable(LEV)) return;
      Object[] params = null;
      if (cmd!=null) { params = cmd.getParams(); }
      StringBuffer sb = new StringBuffer("\n");
      sb.append( (direction==Filter.INCOMING) ? " UP " : "down" );
      sb.append(   "[PermissionFilter]: accept command \""+cmd.getName()+"\"\n");
      sb.append(   "   principal=("+cmd.getPrincipal()+")"
                  +"   credentials=("+cmd.getCredentials()+")\n" );
      if (params!=null)
      for (int i=0; i<params.length; i++)
        sb.append( "     ["+i+"] "+params[i]+"\n");
      myLogger.log( LEV, sb.toString() );
      
  }
    
public static synchronized void log(jade.core.Command cmd) {
    if (!myLogger.isLoggable(LEV)) return;
    Object[] params = null;
    if (cmd!=null) { params = cmd.getParams(); }
    StringBuffer sb = new StringBuffer("\n");
    sb.append(   "[PermissionFilter]: accept command \""+cmd.getName()+"\"\n");
    sb.append(   "   principal=("+cmd.getPrincipal()+")"
                +"   credentials=("+cmd.getCredentials()+")\n" );
    if (params!=null)
    for (int i=0; i<params.length; i++)
      sb.append( "     ["+i+"] "+params[i]+"\n");
    myLogger.log( LEV, sb.toString() );
}

// this contains the mapping  (cmd name) <-> (checkers)
public class CheckerTable {
      private Hashtable map = new Hashtable();
      public void add( String command_name, CommandChecker checker ) {
        Vector checkers = (Vector)map.get( command_name );
        if (checkers == null) {
            checkers = new Vector();
             map.put(command_name, checkers);
        }
        if ( ! checkers.contains( checker ) ) {
             checkers.addElement(checker);
             map.put(command_name, checkers);
        }
      } // end add()
      public Vector get( String command_name ) { return (Vector) map.get(command_name); }
      public int size() { return map.size(); }
} // end CheckerTable

public interface CheckerTableFiller {
      public void fillChecherTable( PermissionFilter pf );
  }
} // end class PermissionFilter
