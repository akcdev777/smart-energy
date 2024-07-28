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

package jade.security.util;


/**
   @author Giosue Vitaglione - Telecom Italia LAB
 
   @see java.security.Principal
*/
public class LocalName implements java.security.Principal, jade.util.leap.Serializable {

  private String name="";
  
  // constructors
  public LocalName(String name) { this.name=name; }
  
  public String getName() { return name; }

  public String toString() {return name; }


  public static String toString(LocalName[] locnames) {
    StringBuffer str= new StringBuffer();
    for (int i=0; i<locnames.length; i++) {
      str.append( locnames[i].toString() );
      if (i<locnames.length-1) str.append(",");
    }
    return str.toString();
  }


  public static LocalName[] getLocalName(String[] locnames) {
    LocalName[] p=new LocalName[locnames.length];
    for (int i=0; i<locnames.length; i++) 
      p[i] = new LocalName( locnames[i] );
    return p;
  }


} // end class LocalName
