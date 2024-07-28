package test.common.testSuite;

import jade.core.AID;
import jade.core.behaviours.ActionExecutor;
import jade.core.behaviours.OneShotBehaviour;
import jade.core.behaviours.OutcomeManager;
import jade.core.behaviours.SequentialBehaviour;
import test.common.TestUtility;
import test.common.testerAgentControlOntology.ExecResult;
import test.common.testerAgentControlOntology.Execute;
import test.common.testerAgentControlOntology.Exit;
import test.common.testerAgentControlOntology.TesterAgentControlOntology;
import test.common.xml.FunctionalityDescriptor;

public class TesterSupervisor extends SequentialBehaviour {
	
	private FunctionalityDescriptor funcDesc = null;
	private ExecResult tgResult = null;
	private String errorMessage = null;
	
	public TesterSupervisor(FunctionalityDescriptor f, long totalGroupExecutionTimeout) {
		super();
		funcDesc = f;
		
		// 1st Step: Load the TesterAgent that will execute the TestGroup
		addSubBehaviour(new OneShotBehaviour(myAgent) {
			public void action() {
				try {
					TestUtility.createAgent(myAgent, TestSuiteAgent.TESTER_NAME, funcDesc.getTesterClassName(), new String[] {"true", myAgent.getLocalName()}, null, null);
				}
				catch (Exception e) {
					e.printStackTrace();
					TesterSupervisor.this.skipNext();
				}
			} 
		});
		
		// 2nd Step: Request the TesterAgent to execute the TestGroup and collect result
		AID tester = new AID(TestSuiteAgent.TESTER_NAME, AID.ISLOCALNAME);
		ActionExecutor ae = new ActionExecutor<Execute, jade.util.leap.List>(new Execute(false), TesterAgentControlOntology.getInstance(), tester) {
			public int onEnd() {
				int ret = super.onEnd();
				if (this.getOutcome().isSuccessful()) {
					jade.util.leap.List l = getResult();
					tgResult = (ExecResult) l.get(0);
				}
				else {
					errorMessage = this.getErrorMsg();
				}
				return ret;
			}
		};
		ae.setTimeout(totalGroupExecutionTimeout);
		addSubBehaviour(ae);
		
		// 3th Step: kill the TesterAgent
		addSubBehaviour(new ActionExecutor<Exit, Void>(new Exit(), TesterAgentControlOntology.getInstance(), tester) {
			public int onEnd() {
				TestSuiteAgent.waitABit();
				return super.onEnd();
			}
		} );
	}
	
	public int onEnd() {
		return 0;
	} 
	
	public ExecResult getResult() {
		return tgResult;
	}
	
	public String getErrorMessage() {
		return errorMessage;
	}
}
