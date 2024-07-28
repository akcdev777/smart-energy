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

package jade.security.util;

import java.security.MessageDigest;
import java.math.BigInteger;
import jade.security.util.DES.Crypt;

/**
        This class calculate the hash of a string using 
        a specified hashing algorithm.

        @author Michele Tomaiuolo - Universita` di Parma
        @author Giosue Vitaglione - TILAB S.p.A.
        @version $Date: 2004-07-20 15:31:25 +0200 (mar, 20 lug 2004) $ $Revision: 452 $
*/
public class Digest {

        public static String digest(String message, String algorithm) {
                return digest(message.getBytes(), algorithm);
        }

        /*
         *  returns the DES digest of 'message' using 'salt'
         *  'algorithm' here can be only "DES"
         *
         */
        public static String digest(byte[] message, String algorithm, String salt) {
                 if (algorithm.compareTo("DES")!=0) { 
                        return "only-DES";
                }
                // Calculate DES "hash" with the provided key
                return jade.security.util.DES.Crypt.crypt( salt, new String(message) ); 

        } // end digest (byte[], String, String) for DES


        /*
         *  returns the digest of 'message' using a specified 'algorithm'
         *  The provided algorithm has to be supported in JCE
         *
         */
        public static String digest(byte[] message, String algorithm) {
                // Use a hashing function supported in Java
                try {
                        MessageDigest md = MessageDigest.getInstance(algorithm);
                        md.reset();
                        md.update(message);
                        byte[] dgst = md.digest();
                        return new BigInteger(+1, dgst).toString(16);
                }
                catch (Exception e) {
                        e.printStackTrace();
                }
                return "###";
        } // end digest()



        public static void main(String[] args) {

                if ( (args.length == 3) && (args[0].compareTo("DES")==0) ) {
                        System.out.println(digest( args[1].getBytes(), "DES", args[2]));
                } else { 
                        if (args.length > 1) {
                                System.out.println( digest(args[1], args[0] ));
                        } else {
                                System.out.println("\nusage: java jade.security.impl.Digest <algorithm> <message> [<salt>]\n");
                                System.out.println(" Examples: ");
                                System.out.println("   java jade.security.impl.Digest MD5 password");
                                System.out.println("   java jade.security.impl.Digest DES password sa");
                        }
                }
        } // end main()
} // end class



