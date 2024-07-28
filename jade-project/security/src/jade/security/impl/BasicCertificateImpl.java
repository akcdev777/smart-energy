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


package jade.security.impl;

import jade.security.*;
import jade.security.util.SecurityData;
import jade.security.util.CredentialsEngine;

import jade.util.leap.ArrayList;
import jade.util.leap.Iterator;
import jade.util.leap.List;

import java.security.Permission;

import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import java.io.*;

//public class BasicCertificateImpl implements jade.security.JADECertificate, jade.util.leap.Serializable {
public class BasicCertificateImpl implements jade.security.JADECertificate {
	
	private JADEPrincipal subject;
	private JADEPrincipal issuer;
	private JADEPrincipal initiator;
	
	private Date notBefore;
	private Date notAfter;

	private long serial;
	
	private ArrayList permissions = new ArrayList();
	
	private SecurityData signature;
	
	public BasicCertificateImpl() {
	}

	public BasicCertificateImpl(byte[] encoded) throws CertificateException {
                try {
                  decode(encoded);
                }
                catch (IOException ex) {
                  throw new CertificateException( ex.getMessage() );
                }
/*
		String[] lines = new String(encoded).split("\n");

		setSubject(decodePrincipal(lines[0]));
		setNotBefore(decodeDate(lines[1]));
		setNotAfter(decodeDate(lines[2]));
		this.signature.data = decodeBytes(lines[3]);

		for (int i = 4; i < lines.length; i++) {
			addPermission(decodePermission(lines[i]));
		}
*/
	}


	public void setSubject(JADEPrincipal subject) {
		this.subject = subject;
	}

	public JADEPrincipal getSubject() {
		return subject;
	}

	public void setIssuer(JADEPrincipal issuer) {
		this.issuer = issuer;
	}

	public JADEPrincipal getIssuer() {
		return issuer;
	}

	public void setInitiator(JADEPrincipal initiator) {
		this.initiator = initiator;
	}

	public JADEPrincipal getInitiator() {
		return initiator;
	}

	public void setSerial(long serial) {
		this.serial = serial;
	}

	public long getSerial() {
		return serial;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	
	public Date getNotAfter() {
		return notAfter;
	}
	
	public void setSignature(SecurityData signature) {
		this.signature = signature;
	}

	public SecurityData getSignature() {
		return signature;
	}
	
	public void addPermission(Object permission) {
		permissions.add(permission);
	}
	
	public void addPermissions(List permissions) {
		for (Iterator i = permissions.iterator(); i.hasNext(); )
			this.permissions.add(i.next());
	}
	
	public List getPermissions() {
		return permissions;
	}
	
	public byte[] getEncoded() throws CertificateEncodingException {
		return toString().getBytes();
	}


  /*
   * Implementation of "Credentials.encode()".
   */
  public byte[] encode() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(baos);
    // Writes the --subject--
    byte[] tmp = CredentialsEngine.encodePrincipal( getSubject() );
    out.writeInt(tmp.length);
    out.write(tmp,0,tmp.length);
    // Write the --signature--
    tmp = CredentialsEngine.encodeSignature( getSignature() );
    out.writeInt(tmp.length);
    out.write(tmp,0,tmp.length);
    // Flush
    return baos.toByteArray();
  }

  /*
   * Implementation of "Credentials.decode()".
   * Currently the encoding only contains the Subject and the Signature 
   */
  public Credentials decode(byte[] enc) throws IOException {
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(enc));
    // Decodes the --subject-- Principal
    int size = in.readInt();
    byte[] data = new byte[size];
    in.read(data,0,size);
    setSubject( CredentialsEngine.decodePrincipal(data) );
    // Decode the --signature--
    size = in.readInt();
    data = new byte[size];
    in.read(data,0,size);
    setSignature ( CredentialsEngine.decodeSignature(data) );    
    return this;
  }


  /*
   * Prints out this certificate.
   * As this method is also used by encode to compute the signature,
   * The printout must not contain the signature
   */
	public String toString() {
		StringBuffer str = new StringBuffer();
		str.append(encodePrincipal(subject)).append('\n');
		str.append(encodeDate(notBefore)).append('\n');
		str.append(encodeDate(notAfter)).append('\n');
		for (Iterator i = getPermissions().iterator(); i.hasNext(); ) {
			Permission p = (Permission)i.next();
			str.append(encodePermission(p)).append('\n');
		}
		return str.toString();
	}
	
	public String encodeDate(Date d) {
		if (d == null)
			return "null";

		return "" + d.getTime();
	}
	
	static Date decodeDate(String s) {
		if (s.equals("null"))
			return null;

		return new Date(Long.parseLong(s));
	}

	public String encodeBytes(byte[] b) {
		if (b == null)
			return "null";

		return new java.math.BigInteger(+1, b).toString(16);
	}
	
	static private byte[] decodeBytes(String s) {
		if (s.equals("null"))
			return null;

		return new java.math.BigInteger(s, 16).toByteArray();
	}

	public String encodePrincipal(JADEPrincipal p) {
		if (p == null)
			return "null";

		return p.getClass().getName() + ' ' + p.toString();
	}
	
	static private JADEPrincipal decodePrincipal(String s) {
		if (s.equals("null"))
			return null;

		JADEPrincipal p = null;
		String[] splitted = s.split(" ");
		try {
			p = (JADEPrincipal)Class.forName(splitted[0]).getConstructor(new Class[] {String.class}).newInstance(new Object[] {splitted[1]});
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return p;
	}
	
	static protected String encodePermission(Permission p) {
		if (p == null)
			return "null";

		StringBuffer str = new StringBuffer();
		str.append(p.getClass().getName());
		if (p.getName() != null) {
			str.append(' ').append(p.getName());
			if (p.getActions() != null)
				str.append(' ').append(p.getActions());
		}
		return str.toString();
	}
	
	static protected Permission decodePermission(String s) {
		if (s.equals("null"))
			return null;

		String type = null;
		String name = null;
		String actions = null;

		String[] splitted = s.split(" ");
		if (splitted.length > 0)
			type = splitted[0];
		if (splitted.length > 1)
			name = splitted[1];
		if (splitted.length > 2)
			actions = s.substring(type.length() + name.length() + 2, s.length());

		return createPermission(type, name, actions);
	}

	static private Permission createPermission(String type, String name, String actions) {
		Permission p = null;
		try {
			if (actions != null)
				p = (Permission)Class.forName(type).getConstructor(new Class[] {String.class, String.class}).newInstance(new Object[] {name, actions});
			else if (name != null)
				p = (Permission)Class.forName(type).getConstructor(new Class[] {String.class}).newInstance(new Object[] {name});
			else
				p = (Permission)Class.forName(type).newInstance();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return p;
	}


      // --- implementation of Credentials interface
      public JADEPrincipal getOwner() {
        return null;
      }
    
      public Enumeration elements() {
        Vector v = (new Vector(1));
        v.add(this);
        return v.elements();
      }
    


}
