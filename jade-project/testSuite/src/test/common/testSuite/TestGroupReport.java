package test.common.testSuite;

import java.util.Map;

import test.common.testerAgentControlOntology.ExecResult;
import test.common.testerAgentControlOntology.TestResult;
import test.common.xml.FunctionalityDescriptor;

public class TestGroupReport {
	
	private FunctionalityDescriptor fd;
	private ExecResult tgResult;
	private String errorMessage;
	private Map<String, TestResult> testsResultMap;

	public TestGroupReport(FunctionalityDescriptor fd, ExecResult tgResult, String errorMessage, Map<String, TestResult> testsResultMap) {
		this.fd = fd;
		this.tgResult = tgResult;
		this.errorMessage = errorMessage;
		this.testsResultMap = testsResultMap;
	}

	public boolean isSuccessful() {
		return tgResult != null;
	}
	
	public int getPassedCnt() {
		return tgResult.getPassed();
	}
	
	public int getFailedCnt() {
		return tgResult.getFailed();
	}
	
	public int getSkippedCnt() {
		return tgResult.getSkipped();
	}
	
	public String getErrorMessage() {
		return errorMessage;
	}

	public Map<String, TestResult> getTestsResultMap() {
		return testsResultMap;
	}

	public void setTestsResultMap(Map<String, TestResult> testsResultMap) {
		this.testsResultMap = testsResultMap;
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder("TestGroupReport for Functionality "+fd.getName()+": ");
		if (isSuccessful()) {
			sb.append("Passed: "+getPassedCnt()).append(", ");
			sb.append("Failed: "+getFailedCnt()).append(", ");
			sb.append("Skipped: "+getSkippedCnt());
		}
		else {
			sb.append("FAILURE - "+getErrorMessage());
		}
		return sb.toString();
	}
}
