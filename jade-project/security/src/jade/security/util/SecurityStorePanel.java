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

package jade.security.util;

import javax.swing.JPanel;
import javax.swing.JFrame;
import jade.core.ProfileImpl;
import jade.core.Profile;
import jade.security.SecurityFactory;
import java.security.KeyPair;
import jade.security.SDSIName;
import jade.security.Name;
import jade.security.impl.SDSINameImpl;
import jade.security.JADEPrincipal;
import javax.swing.JTable;
import java.util.Vector;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Enumeration;
import javax.swing.table.JTableHeader;
import java.awt.BorderLayout;
import java.io.File;
import java.io.FilenameFilter;
import jade.util.Logger;
import java.security.PublicKey;

/**
 *
 * @author Giosue Vitaglione - Telecom Italia Lab
 * @version  $Date: 2010-04-19 16:16:43 +0200 (lun, 19 apr 2010) $ $Revision: 1761 $
 */
public class SecurityStorePanel extends JPanel {

private static String SS_NAME = "ac-jade";
  
private SecurityFactory sf;
private void setup() {
    // --- set Java crypto providers ---
    //java.security.Security.addProvider( new org.bouncycastle.jce.provider.BouncyCastleProvider() );

// ---------------  ----------------

        // --- initialize SecurityFactory
        Profile prof = new ProfileImpl( new jade.util.ExtendedProperties() );
        prof.setParameter(SecurityFactory.SECURITY_FACTORY_CLASS_KEY, 
                         "jade.security.impl.JADESecurityFactory");
        sf = SecurityFactory.getSecurityFactory( prof );
}



private void createstore ()
{
     System.out.println("\n\n --- store creation ---");
     SecurityStore ss = new SecurityStore(SS_NAME);
     ss.generateNewMyKeyPair(512, "RSA");

    // --- Create a JADEPrincipal ---
    KeyPair requester_keypair= SecurityStore.generateNewKeyPair(512, "RSA");
    // SDSIName is composed by the pubkey with the local identifier
    PublicKey pk = requester_keypair.getPublic();
    SDSIName sdsiname = new SDSINameImpl( 
        pk.getEncoded(), pk.getAlgorithm(), pk.getFormat(), new String[]{"capa"} ); // [Pk1, "capa", "."]
    // create the JADEPrincipal
    JADEPrincipal principal = sf.newJADEPrincipal( "noncemale", sdsiname );
    System.out.println( "\n--- principal = "+principal);
    System.out.println( "\n--- encoded principal = "+new String(principal.getEncoded()) );

    // insert the JADEPrincipal into the table: LoacalName<->principal
     ss.setPrincipal("noncemale", principal);

     ss.flush("secret".getBytes());
     ss=null;
}
   
private void openstore()   
{
     System.out.println("\n\n --- store opening ---");
     SecurityStore ss = new SecurityStore("giosue");
     ss.open("secret".getBytes());
     System.out.println( " ss.hasMyKeyPair() = "+ss.hasMyKeyPair() );
     System.out.println( " ss.getMyKeyPair() = "+ss.getMyKeyPair() );
     System.out.println( " ss.getPrincipal(\"noncemale\")=\n"+ss.getPrincipal("noncemale") );

}




SecurityStore ss=null;
/**
 * 
 * @param securityStore
 */
public SecurityStorePanel(SecurityStore securityStore) {
   ss = securityStore;
   setup();
   collect();
   createTable();
} // end constructor







private JTable table=null;
private void createTable() {
   
       // Create a table with initial data
       Vector rowData = new Vector();
       for (Enumeration e = ss.getAllPrincipals(); e.hasMoreElements(); ) {
         JADEPrincipal p = (JADEPrincipal) e.nextElement();

         Name[] locnames = ss.getLocalNames( p );
         String alias = Name.toString( locnames );

         String sdsi_encoded = (p.getSDSIName()!=null) ?  new String (p.getSDSIName().getEncoded()) : "";
         Vector colData = new Vector(
             Arrays.asList(new Object[] {
                           alias, 
                           p.getName(), 
                           sdsi_encoded, 
                           "---" 
         })
             );
         rowData.add(colData);
       }

       String[] columnNames = {
           "Local alias", "Name", "Pub.Key                      ", "Date"};
       Vector columnNamesV = new Vector(Arrays.asList(columnNames));

       table = new JTable(rowData, columnNamesV);
       table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

       JTableHeader header = table.getTableHeader();
       //table.getColumnModel().getColumn(1).setHeaderValue("New Name");
       setLayout(new BorderLayout());
       // Add header in NORTH slot
       add(header, BorderLayout.NORTH);
       // Add table itself to CENTER slot
       add(table, BorderLayout.CENTER);

//add(table);

} // end createTable





private void ins() {

   // --- set Java crypto providers ---
   //java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
   // --- initialize SecurityFactory
   Profile prof = new ProfileImpl( new jade.util.ExtendedProperties() );
   prof.setParameter(SecurityFactory.SECURITY_FACTORY_CLASS_KEY,
                     "jade.security.impl.JADESecurityFactory");
   SecurityFactory sf = SecurityFactory.getSecurityFactory(prof);

   // --- Create a JADEPrincipal ---
   KeyPair requester_keypair = SecurityStore.generateNewKeyPair(512, "RSA");
   PublicKey pk = requester_keypair.getPublic();
   // SDSIName is composed by the pubkey with the local identifier
   SDSIName sdsiname = new SDSINameImpl(
             pk.getEncoded(), pk.getAlgorithm(), pk.getFormat(), new String[]{"capa"} ); // [Pk1, "capa", "."]
   // create the JADEPrincipal
   JADEPrincipal principal = sf.newJADEPrincipal("noncemale", sdsiname);
   System.out.println("\n--- principal = " + principal);
   System.out.println("\n--- encoded principal = " +
                      new String(principal.getEncoded()));

   // insert the JADEPrincipal into the table: LoacalName<->principal
   ss.setPrincipal("noncemale", principal);

   ss.flush("secret".getBytes());
} // end ins()




public static void collect () {

   SecurityStore ss = new SecurityStore( SS_NAME );

   File dir = new File( SecurityStore.getDirName() );
   // list of available ss
   FilenameFilter filter = new FilenameFilter() {
        public boolean accept(File dir, String name) {
            return name.endsWith( SecurityStore.getFileExtension() );
        }
    };
    String[] children = dir.list(filter);

    if (children == null) {
        // Either dir does not exist or is not a directory
    } else {
        for (int i=0; i<children.length; i++) {
            // Get filename of file or directory
            String filename = children[i];
            Logger.println("-"+i+"-"+filename);

            // load the security stores
            String name = filename.substring(0,filename.lastIndexOf(SecurityStore.getFileExtension()) );
            SecurityStore c=new SecurityStore( name );
            c.open("secret".getBytes());
            // get the principal
            JADEPrincipal jp = c.getMyPrincipal();
            // add to the ac map
            ss.setPrincipal( jp.getName(), jp);
            Logger.println("    added: "+jp);
        }
    } // end if-else

    ss.flush("secret".getBytes());

} // end collect()


public static void main (String[] args) {

   String ssName = "ac-jade";
   if (args.length>0) ssName = args[0];
   SecurityStore ss = new SecurityStore( ssName );
   ss.open("secret".getBytes());
   JFrame win = new JFrame();
   JPanel ssp = new SecurityStorePanel( ss );
   win.getContentPane().add( ssp );
   win.pack();
   win.setVisible(true);
} // end main


  
  
} // end class

