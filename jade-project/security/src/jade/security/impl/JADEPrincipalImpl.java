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

import jade.security.JADEPrincipal;
import jade.security.SDSIName;

public class JADEPrincipalImpl
    implements JADEPrincipal, jade.util.leap.Serializable {

  private String name = null;
  private SDSIName sdsiName;

  public JADEPrincipalImpl() {
  }

  /**
   * Create a Principal without associated public key
   */
  public JADEPrincipalImpl(String name) {
    this.name = name;
  }

  /**
   * Create a principal having a certain platform name, 
   * and the specified SDSI name
   */
  public JADEPrincipalImpl(String name, SDSIName sdsiName) {
    this.name = name;
    this.sdsiName = sdsiName;
  }
  
  /**
   * Create a principal having a certain platform name,
   * and the specified SDSI name
   */
  public JADEPrincipalImpl(SDSIName sdsiName) {
    this.name = sdsiName.getLastLocalName();
    this.sdsiName = sdsiName;
  }
  

  /**
   *
   * @return the name of this principal, as known to its platform.
   */
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name=name;
  }


  /**
   *   Returns the SDSIName associated with this Principal
   */
  public SDSIName getSDSIName() {
    return sdsiName;
  } // end getSDSIName()

  public String toString() {
    String retVal = "Principal: "+getName();
    if (sdsiName != null) {
      retVal += SDSINameImpl.SEPARATOR + SDSINameImpl.SEPARATOR + sdsiName.toString();
    }
    return retVal;
  }

  public byte[] getEncoded() {
    return toString().getBytes();
  }

  public boolean implies(JADEPrincipal p) {
    return (p instanceof JADEPrincipalImpl) ? implies( (JADEPrincipalImpl) p) : false;
  }

  public boolean implies(JADEPrincipalImpl p) {
    boolean retVal = false;
    // it is implied if it has the same pub.key and local name
    //PublicKey p1 = sdsiName.getPublicKey();
    //implies( p.getSDSIName() );

    return retVal;
  }


  public boolean equals(Object object) {
    boolean retVal=false;
    if (object==null) return false;
    if (object instanceof JADEPrincipal) {
         retVal = ( (((JADEPrincipal) object).hashCode() ) == (this.hashCode()) );
    }
    return retVal;
  }

  public int hashCode() {
    //System.out.println( " toString() = "+toString() );
    return toString().hashCode();
  }

}
