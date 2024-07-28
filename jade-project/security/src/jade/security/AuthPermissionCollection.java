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

package jade.security;

import jade.security.*;

import jade.core.AID;

import jade.util.leap.List;

import java.security.Permission;
import java.security.PermissionCollection;

import java.util.Enumeration;
import java.util.Hashtable;

public class AuthPermissionCollection extends PermissionCollection { 

	private Hashtable permissions = new Hashtable();

	public void add(Permission permission) {
		if (isReadOnly())
			throw new SecurityException("Attempt to add a Permission to a readonly PermissionCollection");
		if (!(permission instanceof AuthPermission))
			throw new IllegalArgumentException("Invalid permission: " + permission);
		
		String type = permission.getClass().getName();
		String name = permission.getName();
		
		AuthPermission existing = (AuthPermission)permissions.get(name);
		if (existing != null) {
			try {
				String actions = existing.getActions() + "," + permission.getActions();
				AuthPermission combined = (AuthPermission)(Class.forName(type).getConstructor(new Class[] {String.class, String.class}).newInstance(new Object[] {name, actions}));
				permissions.put(name, combined);
			}
			catch (Exception e) { e.printStackTrace(); }
		}
		else {
			permissions.put(name, permission);
		}
	}

	public boolean implies(Permission permission) {
		if (! (permission instanceof AuthPermission))
			return false;

		AuthPermission p = (AuthPermission) permission;

		int desired = p.getActionsMask();
		int effective = 0;
/*
		List implied = p.getTarget().getAllImplied();
		for (int i = 0; i < implied.size(); i++) {
			AuthPermission x = (AuthPermission)permissions.get(((PrincipalImpl)implied.get(i)).getName());
			if (x != null) {
				effective |= x.getActionsMask();
				if ((effective & desired) == desired) {
					return true;
				}
			}
		}
*/
		return false;
	}

	public Enumeration elements() {
		return permissions.elements();
	}
}
