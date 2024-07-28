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

package jade.imtp.rmi;

//#J2ME_EXCLUDE_FILE

import java.io.*;
import java.net.*;
import java.rmi.server.*;
import java.security.KeyStore;
import javax.net.*;
import javax.net.ssl.*;
import javax.security.cert.X509Certificate;

public class SecureSocketFactory implements RMIClientSocketFactory, RMIServerSocketFactory, Serializable {

	transient SSLSocketFactory clientSocketFactory;
	transient SSLServerSocketFactory serverSocketFactory;

	public SecureSocketFactory() {
	}

	/**
		Creates the client socket, which will be used
		to instantiate a <code>UnicastRemoteObject</code>.
		@param host The host to connect to.
		@param port The port to connect to.
		@return The client socket.
	*/
	public Socket createSocket(String host, int port) throws IOException {
		if (clientSocketFactory == null) {
	  	try {
				SSLContext ctx = SSLContext.getInstance("TLS");
				ctx.init(null, null, null);
				clientSocketFactory = (SSLSocketFactory) ctx.getSocketFactory();
	  	}
	  	catch (Exception e) {
	  		throw new IOException("Error creating SSLSocketFactory. "+e.toString());
	  	}
    }
  	SSLSocket sc = (SSLSocket) clientSocketFactory.createSocket(host, port);
  	sc.setEnabledCipherSuites(new String[] {"SSL_DH_anon_WITH_RC4_128_MD5"});
    return sc;
	}

	/**
		Creates the server socket, which will be used
		to instantiate a <code>UnicastRemoteObject</code>.
		@param port The port to listen on.
		@return The server socket.
	*/
	public ServerSocket createServerSocket(int port) throws IOException { 
		if (serverSocketFactory == null) {
			try {
				SSLContext ctx = null;
				ctx = SSLContext.getInstance("TLS");
				ctx.init(null, null, null);
				
				serverSocketFactory = ctx.getServerSocketFactory();
	  	}
	  	catch (Exception e) {
	  		throw new IOException("Error creating SSLServerSocketFactory. "+e.toString());
	  	}
		}

  	SSLServerSocket sss = (SSLServerSocket) serverSocketFactory.createServerSocket(port);
		sss.setEnabledCipherSuites(new String[] {"SSL_DH_anon_WITH_RC4_128_MD5"});
		return sss;
	}

}

