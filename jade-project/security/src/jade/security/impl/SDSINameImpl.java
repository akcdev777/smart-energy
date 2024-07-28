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

import org.apache.commons.codec.binary.Base64;

/**
 * The <code>SDSINameImpl</code> represents
 * a unique identifier for JADE principals
 *
 *@author Giosue Vitaglione - Telecom Italia LAB
 *@version $Date: 2006-01-19 15:04:01 +0100 (gio, 19 gen 2006) $ $Revision: 634 $
 */
public class SDSINameImpl implements jade.security.SDSIName, jade.util.leap.Serializable {

  // TODO: include this with pre-processor directives
  private String name[];
  //private PublicKey publicKey = null;
  private byte[] encoded;
  private String algorithm;
  private String format;

  // used when encoding
  public final static String SEPARATOR = "|";

  private void init(byte[] encoded, String algo, String format) {
    this.encoded = encoded;
    this.algorithm = algo;
    this.format = format; 
  }

  /**
   * Default constructor, no SDSI local name
   */
  public SDSINameImpl(byte[] encoded, String algo, String format) {
    init(encoded,algo,format);
    name = new String[1];
    name[0] = ".";
  }
  
  /**
   * Constructor for simple SDSI name, with one local name
   */
  public SDSINameImpl(byte[] encoded, String algo, String format, String name) {
    init(encoded,algo,format);
    this.name = new String[2];
    this.name[0] = name;
    this.name[1] = ".";
  }

  /**
   *  Constructor for complex SDSI name
   */
  public SDSINameImpl (byte[] e, String a, String f, String[] name) {
    init(e,a,f);
    this.name = name;
  }

  public String getAlgorithm() {
    return algorithm;
    //return publicKey.getAlgorithm();
  }

  public byte[] getEncoded() {
    return encoded;
    //return publicKey.getEncoded();
  }

  public String getFormat() {
    return format;
    //return publicKey.getFormat();
  }

  
  public String toString() {
    int i=0;
    String allNames = name[i];
    while ((++i) < name.length) {
      allNames += SEPARATOR + name[i];
    }
    try {
	    return new String(Base64.encodeBase64(getEncoded()), "US-ASCII") + allNames;
    }
    catch (Exception e) {
    	// Should never happen
    	e.printStackTrace();
    	return null;
    }
  }


  public String[] getLocalNames() {
    return name;
  }

  public String getLastLocalName() {
    String retVal = null;
    if (name.length > 1) {
      return name[name.length - 2];
    } else return ".";
  }

}
