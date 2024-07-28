package test.common.testSuite;

import jade.content.lang.sl.SLCodec;
import jade.wrapper.gateway.GatewayAgent;
import test.common.testerAgentControlOntology.TesterAgentControlOntology;

public class HTSAgent extends GatewayAgent {

	protected void setup() {
		super.setup();
		
		// Register language and ontology used to control the
		// execution of the tester agents
		SLCodec codec = new SLCodec();
		getContentManager().registerLanguage(codec);
		getContentManager().registerOntology(TesterAgentControlOntology.getInstance());
		
		System.out.println("HTSAgent starting");
	} 
}
