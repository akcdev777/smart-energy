/**
 * ***************************************************************
 * JADE - Java Agent DEvelopment Framework is a framework to develop
 * multi-agent systems in compliance with the FIPA specifications.
 * Copyright (C) 2002 TILAB S.p.A.
 * GNU Lesser General Public License
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * version 2.1 of the License.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 * **************************************************************
 */
package jade.imtp.rmi;

//#J2ME_EXCLUDE_FILE

import java.rmi.server.*;

/**
	@author Michele Tomaiuolo - Universita` di Parma
	@version $Date: 2004-07-14 10:19:28 +0200 (mer, 14 lug 2004) $ $Revision: 401 $
*/
public class RMISSLIMTPManager extends RMIIMTPManager {

	SecureSocketFactory socketFactory;

  public RMISSLIMTPManager() {
  	super();
  	socketFactory = new SecureSocketFactory();
  }

	/**
		Creates the client socket factory, which will be used
		to instantiate a <code>UnicastRemoteObject</code>.
		@return The client socket factory.
	*/
	public RMIClientSocketFactory getClientSocketFactory() {
		return socketFactory;
	}

	/**
		Creates the server socket factory, which will be used
		to instantiate a <code>UnicastRemoteObject</code>.
		@return The server socket factory.
	*/
	public RMIServerSocketFactory getServerSocketFactory() { 
		return socketFactory;
	}
}

