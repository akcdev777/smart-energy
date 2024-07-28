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

package jade.domain.FIPAAgentManagement;

/** 
 * SecurityObject is FIPA's generic placeholder to include security related 
 * information into the envelope (such as signature, encryption, kerberos 
 * tickets, etc.)
 * The security information is actually encoded according to the format 
 * specified.
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @author Nicolas Lhuillier - Motorola Labs
 * @author Jerome Picault - Motorola Labs
 * @version  $Date: 2009-08-26 09:30:57 +0200 (mer, 26 ago 2009) $ $Revision: 1708 $
 *
 * @see jade.domain.FIPAAgentManagement.FIPAManagementOntology
 * @see jade.domain.FIPAAgentManagement.Envelope
 */

import jade.util.leap.Serializable;

public class SecurityObject implements Serializable {

	private int     type;
	private String  format;
	private Object  encoded;
	private String  convId;

	/**
	 * Name of the Envelope slot containing SecurityObjects
	 */
	public static String NAME = "X-security";

	/**
	 * The SecurityObject contains a signature
	 */
	public static int SIGN = 1;

	/**
	 * The SecurityObject refers to an encryption
	 */
	public static int ENCRYPT = 2;

	/**
	 * The constructor creates a SecurityObject for the given type
	 **/
	public SecurityObject(int t) {
		type = t;
	}

	public int getType() {
		return type;
	}

	public String getFormat() {
		return format;
	}

	public void setFormat(String f) {
		format = f;
	}

	public Object getEncoded() {
		return encoded;
	}

	public void setEncoded(Object e) {
		encoded = e;
	}

	public String getConversationId(){
		return convId;
	}

	public void setConversationId(String c){
		convId = c;
	}

	public Object clone() {
		SecurityObject cloned = new SecurityObject(type);
		cloned.format = format;
		cloned.encoded = encoded;
		cloned.convId = convId;
		return cloned;
	}
}
