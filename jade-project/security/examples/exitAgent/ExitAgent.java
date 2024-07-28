package exitAgent;

import jade.core.Agent;

public class ExitAgent extends Agent {
  
  public void setup() {
    try {
      System.out.println("\n\n--  ExitAgent started...");

      System.out.println("\n\n--  I'm about to exit the Java Virtual Machine...");

      System.exit(-1);

    } catch (Exception e) {
      e.printStackTrace();
    }
    System.out.println("\n\n--  Wow! I didn't succeed. The JVM is still there, up and running. :-)");

  }
  

  
}

