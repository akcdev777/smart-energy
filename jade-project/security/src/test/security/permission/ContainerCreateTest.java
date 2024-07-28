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
 * @version $Date: 2004-07-14 15:16:06 +0200 (mer, 14 lug 2004) $ $Revision: 416 $
 */

public class ContainerCreateTest
    extends PermissionTest {

  public void action() {

    boolean started = false;

    // START MAIN CONTAINER
    try {
      newPlatform = TestUtility.launchJadeInstance(
          NEW_PLATFORM_NAME, null,
          " -conf " + getTestArgument(MAIN_CONFIG_FILE_KEY) +
          " -java.security.policy " + getTestArgument(MAIN_POLICY_FILE_KEY)
          , null);

      if (newPlatform != null) {
        started = true;
      } else {
        started = false;
      }
    } catch (Exception te) {
      //te.printStackTrace();
      started = false;
    }

    boolean shouldPass = "true".equals(getTestArgument(SHOULD_SUCCEED_KEY));

    StringBuffer msg = new StringBuffer("Main Container");
    if (started) {
      msg.append("started correctly ");
    }
    else {
      msg.append("did not started correctly ");
    }

    if (shouldPass) {
      msg.append("with permissions to do so.");
    }
    else {
      msg.append("without permissions to do so.");
    }

    if (shouldPass == started) {
      passed(msg.toString());
    }
    else {
      failed(msg.toString());
    }

  } // end action

} // end class