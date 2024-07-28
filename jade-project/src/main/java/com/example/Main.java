package com.example;

import jade.core.Profile;
import jade.core.ProfileImpl;
import jade.core.Runtime;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;


/**
 * Hello world!
 *
 */
public class Main
{
    public static void main( String[] args )
    {
        Runtime rt = Runtime.instance();

        // Create a default profile
        Profile profile = new ProfileImpl();
        ContainerController container = rt.createMainContainer(profile);

        try {
            // Create and start the UserAgent
            String identifier = "12345";
            String firstName = "John";
            String lastName = "Doe";
            String address = "123 Elm Street";
            String phoneNumber = "555-1234";
            Object[] agentArgs = {identifier, firstName, lastName, address, phoneNumber};

            AgentController agent = container.createNewAgent("userAgent", "com.example.UserAgent", agentArgs);
            agent.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
