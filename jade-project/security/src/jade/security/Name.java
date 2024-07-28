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

package jade.security;


/**
   This class is used into policy files as principal.
   You can grant permissions to a Name. 

   A service enforcing the policy should handle a Name 
   as, in order of preference, 1) a local alias, 
   2) a GUID, or 3) a local name (unique into the platform).

   @author Giosue Vitaglione - Telecom Italia LAB
 
   @see java.security.Principal
*/
public class Name implements java.security.Principal, jade.util.leap.Serializable {

  private String name="";
  
  // constructors
  public Name(String name) { this.name=name; }

  public String getName() { return name; }

  public String toString() {return name; }


  public static String toString(Name[] names) {
    StringBuffer str= new StringBuffer();
    for (int i=0; i<names.length; i++) {
      str.append( names[i].toString() );
      if (i<names.length-1) str.append(",");
    }
    return str.toString();
  }


  public static Name[] getName(String[] names) {
    Name[] p=new Name[names.length];
    for (int i=0; i<names.length; i++) 
      p[i] = new Name( names[i] );
    return p;
  }


} // end class Name
