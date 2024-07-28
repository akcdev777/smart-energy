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


package test.security.permission;

import jade.core.Agent;
import jade.core.behaviours.Behaviour;
import jade.core.behaviours.OneShotBehaviour;
import jade.core.behaviours.SequentialBehaviour;
import jade.core.security.SecurityHelper;
import test.common.JadeController;
import test.common.Logger;
import test.common.Test;
import test.common.TestException;
import test.common.TestUtility;
import java.security.ProtectionDomain;
import java.security.PermissionCollection;
import java.security.Permission;
import java.security.Policy;
import java.util.Enumeration;



/**
 * @author Giosue.Vitaglione@telecomitalia.it
 * @version $Date: 2004-07-14 18:11:28 +0200 (mer, 14 lug 2004) $ $Revision: 422 $
 */

public class PermissionTest
    extends Test {

  // JADE configuration file name is passed from the xml by this key
  protected static final String MAIN_CONFIG_FILE_KEY = "conf-main";
  protected static final String CONT1_CONFIG_FILE_KEY = "conf-cont1";
  protected static final String MAIN_POLICY_FILE_KEY = "policy-main";
  protected static final String CONT1_POLICY_FILE_KEY = "policy-cont1";
  protected static final String SHOULD_SUCCEED_KEY = "shouldSucceed";


  protected static final String NEW_PLATFORM_NAME = "NewPermissionTestPlaform";
  protected JadeController newPlatform;
  protected JadeController cont1;
  protected JadeController cont2;

  // this is the agent who is executing the test
  private Agent testerAgent=null;
  protected Agent getTesterAgent(){ return testerAgent;}

  public void action(){
  failed(" Method action() should be overwritten by a subclass of PermissionTest");
  }

  public Behaviour load(Agent a) throws TestException {
    testerAgent = a;
    try {

      SequentialBehaviour b1 = new SequentialBehaviour(a);
      b1.addSubBehaviour(new OneShotBehaviour(a) {

        private boolean done = false;

        public void action() {
          PermissionTest.this.action();
        } // end action()
      } //end Behaviour
      );
      return b1;
    }
    catch (Exception e) {
      throw new TestException(e.getMessage());
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see test.common.Test#clean(jade.core.Agent)
   */
  public void clean(Agent a) {
    // Kill the remote container
    if (cont2 != null) {
      cont2.kill();
    }
    if (cont1 != null) {
      cont1.kill();
    }
    if (newPlatform != null) {
      newPlatform.kill();
    }
  }

} // end class