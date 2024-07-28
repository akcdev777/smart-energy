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

import java.security.Permission;

import java.util.StringTokenizer;
import java.security.PermissionCollection;


public class AuthPermission extends java.security.Permission implements jade.util.leap.Serializable {


	public static final String AGENT_NAME = "agent-name";
	public static final String AGENT_OWNER = "agent-owner";  
	public static final String AGENT_CLASS = "agent-class";
	public static final String CONTAINER_OWNER = "container-owner";



	public static final String SEP=",";  // separator between tergets "class=xxx,name=yyy"
	private int mask = 0;
	private transient String actions;



	public AuthPermission(String target, String actions) {
		super(target);
		log("--[AuthPermission]()  target="+target+"  actions="+actions);
		if (target == null)
			throw new NullPointerException("Target can't be null");
		if (actions == null)
			throw new NullPointerException("Actions can't be null");
		this.mask = decodeActions(actions);
	}

	public String getActions() {
		if (actions == null)
			actions = encodeActions(this.mask);
		return actions;
	}

	public int hashCode() {
		//int hashcode=getTarget().hashCode();
		int hashcode=toString().hashCode();              
		return hashcode;
	}


	public boolean equals(Object p) {
		log("\n--[AuthPermission] equals()  p="+p);
		log("--[AuthPermission] equals()   class="+getClass());
		log("--[AuthPermission] equals()  pclass="+p.getClass());

		if (!getClass().isInstance(p)) return false;

		AuthPermission that = (AuthPermission) p;
		log("--[AuthPermission] equals() that.mask="+that.mask);
		return (this.mask == that.mask) &&
		(that.getTarget().equals(getTarget()));
	}


	public boolean implies(Permission p) {
		log("\n--[AuthPermission] ## Does this="+this);
		log("\n--[AuthPermission]    implies(p)?  p="+p);

		if (!getClass().isInstance(p)) return false;

		AuthPermission that = (AuthPermission) p;
		log("--[AuthPermission] this.mask="+this.mask+"   p.mask="+that.mask+"   &"+(this.mask & that.mask));
		boolean result = ((this.mask & that.mask) == that.mask) &&
		that.impliesConstrains(getTarget());
		log("--[AuthPermission] ## implies()  result="+result);
		return result;
	}


	/**
	 *  Returns 'true' if the target of this permission
	 *  implies the target passed as argument.
	 * @return
	 */
	private boolean impliesConstrains(String targets1) {
		// argument 'targets1' is the entry written into the policy file
		// argument 'targets2' is this permission's constrains
		String targets2=getTarget();
		// returns true if 'targets2' are included into 'targets1'
		if ( (targets1==null) ||
				(targets1.equals("")) ||
				(targets1.equals("*"))   ) return true;

		StringTokenizer tokenizer = new StringTokenizer(targets2, ",");
		boolean res=true;
		// All constrains (aka targets) must be accomplished
		boolean done=false;
		while ( (!done) && (tokenizer.hasMoreTokens()) ) {
			// single constrain of the permission to be checked
			String cons2 = tokenizer.nextToken();
			int cmp = targetsVsSingle( targets1, cons2 );
			// cmp=0, do not intersect
			// cmp=1, cons1 includes cons2, ok
			// cmp=2, cons1 is stricter than cons2
			// cmp=-1, malformed
			if (cmp==2) { res=false; done=true; }
			if (cmp==-1) { res=false; done=true; }
		}
		return res;
	}

	// returns true if the target (i.e. constrains) of this permission 
	// includes the given single constrain
	private static int targetsVsSingle(String targets1, String cons2) {
		// 'target1' can contain more constrains (from the policy)
		// 'cons2' contains a single constrain
		int cmpTot=0;
		StringTokenizer tokenizer = new StringTokenizer(targets1, ",");
		// at least one must be accomplished
		while ( (cmpTot==0) && (tokenizer.hasMoreTokens()) ) {
			String cons1 = tokenizer.nextToken();
			int cmp = singleVsSingle( cons1, cons2 );
			// cmp=0, do not intersect
			// cmp=1, cons1 includes cons2, ok
			// cmp=2, cons1 is stricter than cons2
			// cmp=-1, malformed
			if (cmp==1) cmpTot=1;
			if (cmp==2) cmpTot=2;
		}
		return cmpTot;
	}

	private static int singleVsSingle(String cons1, String cons2) {
		// returns: 
		// cmp=0, do not intersect
		// cmp=1, cons1 includes cons2, ok
		// cmp=2, cons1 is stricter than cons2
		// cmp=-1, malformed

		int idx = cons1.indexOf('=');
		if (idx<0) return -1;
		String key= cons1.substring(0, idx);
		String val= cons1.substring(idx+1);
		int idx2 = cons2.indexOf('=');
		if (idx2<0) return -1;
		String key2= cons2.substring(0, idx2);
		String val2= cons2.substring(idx2+1);

		int cmp=0;
		if (!key.equals(key2)){
			return 0; // constrains do not intersect
		}
		// both are the same constrain type, go on

		// --------------------
		if (key.equals(AGENT_CLASS)) {
			cmp = (
					( val.equals("*")) // wild card
					||( val.equals(val2)) // exact match
					||( includedPackage(val2, val)) // wild card for sub-packages 
			) ? 1:2;
		} else
			if (key.equals(AGENT_NAME)) {
				cmp = (
						( val.equals("*") ) 
						|| ( cons1.equals(cons2)  )
						|| ( wildEquals(val2, val)) // wild card compare for Strings 
				) ? 1:2;
			} else 
				if (key.equals(AGENT_OWNER)) {
					cmp = (
							( val.equals("*") ) ||
							( cons1.equals(cons2)  )
					) ? 1:2;
				} else 
					if (key.equals(CONTAINER_OWNER)) {
						cmp = (
								( val.equals("*") ) ||
								( cons1.equals(cons2)  )
						) ? 1:2;
					} else 
						if (key.equals("...")) {
							// other constrain type...
						}


		return cmp;
	}

	public String getTarget() {
		String name=getName(); // calls the parent, java calls that "name"
		return name;
	}
	/*
        public PermissionCollection newPermissionCollection() {
                return new AuthPermissionCollection();
        }
	 */
	int getActionsMask() {
		return mask;
	}

	public String[] getAllActions() {
		return new String[] {};
	}

	private int decodeActions(String actions) {
		int mask = 0;
		if (actions == null)
			return mask;

		String[] allActions = getAllActions();
		StringTokenizer tokenizer = new StringTokenizer(actions, ", \r\n\f\t");
		while (tokenizer.hasMoreTokens()) {
			String action = tokenizer.nextToken();
			for (int i = 0; i < allActions.length; i++) {
				if (action.equals(allActions[i])) {
					mask |= 1 << i;
					continue;
				}
			}
		}
		return mask;
	}

	private String encodeActions(int mask) {
		StringBuffer sb = new StringBuffer();
		boolean comma = false;
		String[] allActions = getAllActions();

		for (int i = 0; i < allActions.length; i++) {
			int onebit = 1 << i;
			if ((mask & onebit) == onebit) {
				if (comma) sb.append(',');
				else comma = true;
				sb.append(allActions[i]);
			}
		}

		return sb.toString();
	}

	public String toString() {
		return "(" + getClass().getName() + " \"" + getTarget() + "\", \"" + getActions() + "\")";
	}

	// returns true if a includes b
	private static boolean includedPackage(String val2, String val) {
		boolean res=false;
		// val2=jade.xxx.blabla  val=jade.xxx.*  -> true
		// val2=jade.xxx.blabla  val=jade.*      -> true
		int starpos = val.lastIndexOf("*");
		if (starpos<1) return false;
		if ( val2.startsWith( 
				val.substring(0,starpos-1) 
		)) { res=true; }
		return res;
	}

	// returns true if val2 is equal to pat (pat can contain * and ? wildcards)
	private static boolean wildEquals(String val2, String pat) {
		// val2=blabla  pat=bla*  -> true
		// val2=blabla  pat=bla???      -> true
		boolean equal = true;
		int i=-1;
		int n=pat.length(); 
		if (n>val2.length()) n=val2.length();
		while( (++i<n) && (equal) ) {
			char p = pat.charAt(i); // pat is the pattern
			//System.out.println(" i="+i+"     p="+p+"    p==?"+(p=='?'));
			if (p=='*') { 
				i=pat.length(); // skip the rest
			} else {
				if (! ((p==val2.charAt(i)) || (p=='?')) ) { equal=false; }
			}
		}// end for
		return equal;
	}

	private static void log(String a) {
		//System.out.println( a );
	}
}
