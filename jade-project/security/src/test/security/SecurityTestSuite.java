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

package test.security;

import test.common.testSuite.TestSuiteAgent; 
import test.common.Test; 
import test.common.TestUtility; 
import jade.core.Profile;
import jade.core.ProfileImpl;
import jade.core.Runtime;
import jade.wrapper.AgentContainer;
import jade.wrapper.AgentController;
import jade.core.security.SecurityService;
import jade.core.security.permission.PermissionService;

/**
 * @author Nicolas Lhuillier - Motorola
 * @version $Date: 2004-07-16 15:35:21 +0200 (ven, 16 lug 2004) $ $Revision: 431 $
 */
public class SecurityTestSuite extends TestSuiteAgent {

  public static final String SECURITY_SERVICES = "jade.core.security.SecurityService;jade.core.security.signature.SignatureService;jade.core.security.encryption.EncryptionService;jade.core.event.NotificationService";
  
  private static final String NAME = "Security-Test-Suite";

  // Main method that allows launching the SecurityTestSuite as a
  // stand-alone program
  public static void main(String[] args) {
    try {   
      // Launch the Main container in a separated process with no security service
      TestUtility.launchJadeInstance("Main", null, "-gui -nomtp -local-port "+Test.DEFAULT_PORT+" -name "+TEST_PLATFORM_NAME+" -services "+SECURITY_SERVICES+" -"+SecurityService.AUTHENTICATION_LOGINMODULE_KEY+" SingleUser", null);
      
      // Get a hold on JADE runtime
      Runtime rt = Runtime.instance();




      // Exit the JVM when there are no more containers around
      rt.setCloseVM(true);
      Profile p = new ProfileImpl(null, Test.DEFAULT_PORT, null);
      p.setParameter(Profile.MAIN, "false");
      p.setParameter(SecurityService.AUTHENTICATION_LOGINMODULE_KEY, "SingleUser");
      p.setParameter(Profile.SERVICES, SECURITY_SERVICES);
      AgentContainer  mc = rt.createAgentContainer(p);
      AgentController testSuite = mc.createNewAgent(NAME, SecurityTestSuite.class.getName(), new String[]{"test/securityTester.xml"});
      testSuite.start();
    } 
    catch (Exception e) {
      e.printStackTrace();
    } 
  } 
}
