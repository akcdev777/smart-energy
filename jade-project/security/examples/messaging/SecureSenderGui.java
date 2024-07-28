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
package messaging;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import jade.lang.acl.ACLMessage;
import jade.gui.AclGui;

public class SecureSenderGui extends JFrame {
	private SecureSenderAgent myAgent;
	private ACLMessage lastMsg = new ACLMessage(ACLMessage.ACCEPT_PROPOSAL);
	
	private JCheckBox signB, encryptB;
	private boolean sign, encrypt;
	
	public SecureSenderGui(SecureSenderAgent a) {
		super(a.getName());
		myAgent = a;
		
		sign = false;
		encrypt = false;
		
		setSize(getProperSize(240, 100));
		setResizable(false);
		
		JPanel p = null;
		
		p = new JPanel();
		p.setLayout(new GridLayout(1, 2));

		signB = new JCheckBox("Sign message");
		signB.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sign = !sign;
			} 
		} );
		p.add(signB);
		
		
		encryptB = new JCheckBox("Encrypt message");
		encryptB.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				encrypt = !encrypt;
			} 
		} );
		p.add(encryptB);
		
		getContentPane().add(p, BorderLayout.CENTER);
		
		// Command buttons
		p = new JPanel();
		JButton b1 = new JButton("Message");
		b1.addActionListener(new ActionListener(){
	  	public void actionPerformed(ActionEvent e) {
	  		ACLMessage msg = AclGui.editMsgInDialog(lastMsg, SecureSenderGui.this);
	  		if (msg != null) {
		  		myAgent.sendMessage(msg, sign, encrypt);
		  		lastMsg = msg;
	  		}
	  	}
		} );
		JButton b2 = new JButton("Exit");
		b2.addActionListener(new ActionListener(){
	  	public void actionPerformed(ActionEvent e) {
	  		myAgent.doDelete();
	  	}
		} );
		b2.setPreferredSize(b1.getPreferredSize());
		p.add(b1);
		p.add(b2);
		getContentPane().add(p, BorderLayout.SOUTH);
				
		// Window closure
		addWindowListener(new	WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				myAgent.doDelete();
			}
		} );
	}

	public void showCorrect(){
    // Get the size of the default screen
    Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
    int scrH = (int) dim.getHeight();
    int scrW = (int) dim.getWidth();
    setLocation((int) (scrW * 0.2), (int) (scrH * 0.1) );
    show();
	}
	
	private Dimension getProperSize(int maxX, int maxY) {
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		int x = (screenSize.width < maxX ? screenSize.width : maxX);
		int y = (screenSize.height < maxY ? screenSize.height : maxY);
		return new Dimension(x, y);
	}		
}
	