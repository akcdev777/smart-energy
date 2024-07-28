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

import jade.security.util.SOCodec;
import jade.security.util.SecurityData;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/** 
 * Default implementation of the <code>SOCodec</code>.
 * Uses Java serialization to encode the information.
 *
 * @see jade.domain.FIPAAgentManagement.SecurityObject
 * @see jade.security.util.SOCodec
 * @see jade.security.util.SecurityData
 *
 * @author Jerome Picault - Motorola
 * @author Nicolas Lhuillier - Motorola
 * @version  $Date: 2004-07-20 15:31:25 +0200 (mar, 20 lug 2004) $ $Revision: 452 $
 */

public class BasicSOCodec implements SOCodec {
  
  public String getName() {
    return "JADE";
  }
  

  /**
   * Encodes a <code>SecurityData</code> object into a byte sequence,
   * according to the specific object representation.
   * @param so The security object to encode.
   * @return a byte array, containing the encoded security object.
   */
  public byte[] encode(SecurityData so) throws SOCodec.CodecException {
    try { 
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(baos); 
      oos.writeObject(so);
      return baos.toByteArray();
    }
    catch(Exception e) {
      throw new SOCodec.CodecException(e.getMessage(),e);
    }
  }

  /**
   * Recovers a <code>SecurityData</code> object back from raw data,
   * using the specific security object representation to interpret the byte
   * sequence.
   * @param data The byte sequence containing the encoded message.
   * @return A new <code>SecurityData</code> object, built from the raw
   * data.
   * @exception CodecException If some kind of syntax error occurs.
   */
  public SecurityData decode(byte[] data) throws SOCodec.CodecException {
    try{
      ByteArrayInputStream bais = new ByteArrayInputStream(data);
      ObjectInputStream ois = new ObjectInputStream(bais); 
      return (SecurityData)ois.readObject();
    }
    catch(Exception e) {
      throw new SOCodec.CodecException(e.getMessage(),e);
    }
  }
}
