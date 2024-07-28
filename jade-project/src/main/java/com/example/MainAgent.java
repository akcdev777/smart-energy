package com.example;
import jade.core.Agent;
import jade.core.behaviours.Behaviour;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;
import jade.wrapper.StaleProxyException;
public class MainAgent extends Agent {

    @Override
    protected void setup() {
        // Print a welcome message
        System.out.println("Agent " + getLocalName() + " started.");

        // Create a default profile
        jade.core.Runtime rt = jade.core.Runtime.instance();
        jade.core.Profile profile = new jade.core.ProfileImpl();
        jade.wrapper.AgentContainer container = rt.createAgentContainer(profile);

        try {
            // Create and start the UserAgent
            String identifier = "12345";
            String firstName = "ma1";
            String lastName = "Agent";
            String address = "N/A";
            String phoneNumber = "N/A";
            Object[] agentArgs = {identifier, firstName, lastName, address, phoneNumber};

            AgentController agent = container.createNewAgent("userAgent", "com.example.UserAgent", agentArgs);
            agent.start();
        } catch (StaleProxyException e) {
            e.printStackTrace();
        }

    }

}