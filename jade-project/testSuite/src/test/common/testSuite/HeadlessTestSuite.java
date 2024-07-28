package test.common.testSuite;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import jade.content.Predicate;
import jade.core.Profile;
import jade.core.behaviours.CyclicBehaviour;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;
import jade.wrapper.gateway.GatewayAgent;
import jade.wrapper.gateway.JadeGateway;
import test.common.JadeController;
import test.common.Test;
import test.common.TestUtility;
import test.common.TesterAgent;
import test.common.testerAgentControlOntology.NumberOfTests;
import test.common.testerAgentControlOntology.TestResult;
import test.common.xml.FunctionalityDescriptor;
import test.common.xml.XMLManager;

public class HeadlessTestSuite {
	
	public static final int NO_INTERRUPT = 0;
	public static final int INTERRUPT_ON_TEST_FAILURE = 1;
	public static final int INTERRUPT_ON_GROUP_FAILURE = 2;

	public JadeController mainController;
	
	private TestGroupNotificationReceiver tgnReceiver;

	/**
	 * Initialize the test environment starting a MainContainer with default configurations 
	 * then connect to it via a JadeGateway
	 */
	public void initialize() throws Exception {
		initialize(null, null);
	}
	
	/**
	 * Initialize the test environment starting a MainContainer with default configurations plus 
	 * additional configurations if needed, then connect to it via a JadeGateway with custom configurations
	 * @param additionalConfig OPTIONAL: Additional configurations to be passed to the Main Container
	 * @param pp OPTIONAL: custom configurations to be passed to the local JadeGateway
	 */
	public void initialize(Properties mainAdditionalConfig, Properties pp) throws Exception {
		if (isConnected()) {
			throw new IllegalStateException("HeadlessTestSuite already connected");
		}
		
		// Launch the Main container in a separated process
		mainController = TestUtility.launchJadeInstance("Main", null, "-nomtp -local-port "+Test.DEFAULT_PORT+" -services "+TestSuiteAgent.MAIN_SERVICES+" -name "+TestSuiteAgent.TEST_PLATFORM_NAME+" "+asCommandLine(mainAdditionalConfig)+" -jade_domain_df_autocleanup true", null);

		if (pp == null) {
			pp = new Properties();
		}
		pp.setProperty(Profile.MAIN, "false");
		pp.setProperty(Profile.SERVICES, "jade.core.event.NotificationService;jade.core.mobility.AgentMobilityService;jade.core.replication.AddressNotificationService;jade.core.messaging.TopicManagementService");
		connect(pp);
	}
	
	/**
	 * Connect to an already running platform where tests will be executed  
	 * @param pp The properties to initialize the JadeGateway used to interact with the 
	 * running platform.
	 */
	public void connect(Properties pp) throws Exception {
		if (isConnected()) {
			throw new IllegalStateException("HeadlessTestSuite already connected");
		}
		
		JadeGateway.init(HTSAgent.class.getName(), jade.util.leap.Properties.toLeapProperties(pp));
		tgnReceiver = new TestGroupNotificationReceiver();
		JadeGateway.execute(tgnReceiver);
	}

	public boolean isConnected() {
		return tgnReceiver != null && tgnReceiver.getAgent() != null;
	}
	
	/**
	 * Execute the TestGroup targeting a given functionality
	 * @param fd The Descriptor of the functionality to be tested and the tests to execute
	 * @param l An optional TestListener to handle notifications about completion of single 
	 * tests as long as they are executed.
	 * @return A TestGroupReport holding the results of all executed tests 
	 * @throws Exception If an error occurs
	 */
	public TestGroupReport executeTestGroup(FunctionalityDescriptor fd, TestListener l) throws Exception {
		if (!isConnected()) {
			throw new IllegalStateException("HeadlessTestSuite not connected");
		}
		tgnReceiver.getTestsResultMap().clear();
		tgnReceiver.setTestListener(l);
		TesterSupervisor s = new TesterSupervisor(fd, 0); 
		JadeGateway.execute(s);
		return new TestGroupReport(fd, s.getResult(), s.getErrorMessage(), tgnReceiver.getTestsResultMap());
	}

	public TestSuiteReport executeTestSuite(String xmlFileName, int failureHandlingPolicy) throws Exception {
		if (!isConnected()) {
			throw new IllegalStateException("HeadlessTestSuite not connected");
		}
		
		if (xmlFileName == null) {
			xmlFileName = "test/testerList.xml";
		}
		
		TestSuiteReport globalReport = new TestSuiteReport();
		FunctionalityDescriptor[] ffdd = XMLManager.getFunctionalities(xmlFileName);
		for (FunctionalityDescriptor fd : ffdd) {
			if (!fd.getSkip()) {
				TestGroupReport report = executeTestGroup(fd, null);
				globalReport.addGroupReport(report);
				if (failureHandlingPolicy == INTERRUPT_ON_TEST_FAILURE) {
					if (report.getFailedCnt() > 0) {
						break;
					}
				}
				else if (failureHandlingPolicy == INTERRUPT_ON_GROUP_FAILURE) {
					if (!report.isSuccessful()) {
						break;
					}
				}
			}
		}
		globalReport.computeSummary();
		return globalReport;
	}
	
	static String asCommandLine(Properties pp) {
		// FIXME: To be implemented
		return "";
	}

	/**
	 * INNER CLASS: TestGroupNotificationReceiver
	 * Handle messages from a TesterAgent notifying the progress and completion of the executed TestGroup
	 */
	class TestGroupNotificationReceiver extends CyclicBehaviour {
		
		private Map<String, TestResult> testsResultMap = new HashMap<String, TestResult>();
		private TestListener listener;
		private int numberOfTests;

		private MessageTemplate templ = MessageTemplate.and(
				MessageTemplate.MatchPerformative(ACLMessage.INFORM), 
				MessageTemplate.MatchConversationId(TesterAgent.TEST_NOTIFICATION));

		public TestGroupNotificationReceiver() {
			super();
		}
		
		Map<String, TestResult> getTestsResultMap() {
			return testsResultMap;
		}
		
		void setTestListener(TestListener l) {
			listener = l;
		}

		public void onStart() {
			System.out.println("onStart()");
			// Immediately notify the GatewayAgent to make the JadeGateway.execute() method return
			if (myAgent instanceof GatewayAgent) {
				((GatewayAgent) myAgent).releaseCommand(this);
				System.out.println("Command released");
			}
		}
		
		public void action() {
			ACLMessage msg = myAgent.receive(templ);
			if (msg != null) {
				try {
					Predicate p = (Predicate) myAgent.getContentManager().extractContent(msg);
					if (p instanceof TestResult) {
						TestResult tr = (TestResult) p;
						testsResultMap.put(tr.getName(), tr);
						if (listener != null) {
							listener.handleTestResult(tr);
						}
					}
					else if (p instanceof NumberOfTests) {
						NumberOfTests not = (NumberOfTests) p;
						numberOfTests = not.getN();
					}
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			} 
			else {
				block();
			} 
		} 
	}
	
	
	
	public static interface TestListener {
		void handleTestResult(TestResult r);
	}
	
	
	public static void main(String[] args) {
		try {
			HeadlessTestSuite hts = new HeadlessTestSuite();
			Properties pp = new Properties();
			pp.setProperty(Profile.GUI, "true");
			hts.initialize(pp, null);
			
			String xmlFileName = null;
			if (args != null && args.length > 0) {
				xmlFileName = args[0];
			}
			TestSuiteReport report = hts.executeTestSuite(xmlFileName, NO_INTERRUPT);
			System.out.println(report);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
//	public static void main(String[] args) {
//		try {
//			HeadlessTestSuite hts = new HeadlessTestSuite();
//			hts.initialize();
//			String xmlFileName = "test/testerList.xml";
//			FunctionalityDescriptor[] ffdd = XMLManager.getFunctionalities(xmlFileName);
//			TestGroupReport report = hts.executeTestGroup(ffdd[3], null);
//			System.out.println(report);
//		}
//		catch (Exception e) {
//			e.printStackTrace();
//		}		
//	}
}
