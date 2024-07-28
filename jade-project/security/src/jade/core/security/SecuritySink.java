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
package jade.core.security;

import jade.core.GenericCommand;
import jade.core.Sink;
import jade.core.VerticalCommand;

/**
 * @author Ivan Trencansky - Whitestein Technologies
 * @version  $Date: 2004-07-31 14:49:17 +0200 (sab, 31 lug 2004) $ $Revision: 485 $
 */
public class SecuritySink implements Sink {

	/* (non-Javadoc)
	 * @see jade.core.Sink#consume(jade.core.VerticalCommand)
	 */
	public void consume(VerticalCommand cmd) {

//		Object result = null;
//		
//		try {
//			String cmdName = cmd.getName();
//			if (cmdName.equals(SecurityHelper.AUTHENTICATE_USER)) {
//				Logger.println(
//					"\n\nSecuritySink -> processing command: "
//						+ cmd.getName()
//						+ "\n\n");
//				UserAuthenticator ua = new UserAuthenticator();
//				result = ua.authenticateUser();
//			} else {
//				Logger.println(
//					"\n\nSecuritySink -> received unsupported command: "
//						+ cmd.getName()
//						+ "\n\n");
//			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			cmd.setReturnValue(e);
//		}
//		cmd.setReturnValue(result);
	}

	public static void main(String[] args) {
		SecuritySink ats = new SecuritySink();

		ats.consume(
			new GenericCommand(
				SecurityService.AUTHENTICATE_USER,
				"jade.core.event.Authentication",
				""));
		System.exit(-1);
	}

}
