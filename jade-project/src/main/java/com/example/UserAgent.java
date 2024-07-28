package com.example;
import jade.core.Agent;
import jade.core.behaviours.Behaviour;
public class UserAgent extends Agent{
    private String identifier;
    private String firstName;
    private String lastName;
    private String address;
    private String phoneNumber;


    @Override
    protected void setup() {
        // Print a welcome message
        System.out.println("Agent " + getLocalName() + " started.");

        // Initialize user details from arguments
        Object[] args = getArguments();
        if (args != null && args.length == 5) {
            identifier = (String) args[0];
            firstName = (String) args[1];
            lastName = (String) args[2];
            address = (String) args[3];
            phoneNumber = (String) args[4];

            System.out.println("User Details: ");
            System.out.println("Identifier: " + identifier);
            System.out.println("First Name: " + firstName);
            System.out.println("Last Name: " + lastName);
            System.out.println("Address: " + address);
            System.out.println("Phone Number: " + phoneNumber);
        } else {
            System.out.println("No user details provided.");
            doDelete();
        }

        // Add a simple behavior
        addBehaviour(new UserBehaviour());
    }

    private class UserBehaviour extends Behaviour {
        @Override
        public void action() {
            // Implement the behavior
            System.out.println("Agent " + getLocalName() + " is performing an action.");
        }

        @Override
        public boolean done() {
            return true;
        }
    }
}
