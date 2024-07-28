package test.common.testSuite;

import java.util.ArrayList;
import java.util.List;

public class TestSuiteReport {
	private int totalPassed = 0;
	private int totalFailed = 0;
	private int totalSkipped = 0;

	private List<TestGroupReport> groupReports = new ArrayList<TestGroupReport>();

	public int getTotal() {
		return totalPassed + totalFailed + totalSkipped;
	}

	public int getTotalPassed() {
		return totalPassed;
	}

	public int getTotalFailed() {
		return totalFailed;
	}

	public int getTotalSkipped() {
		return totalSkipped;
	}

	public List<TestGroupReport> getGroupReports() {
		return groupReports;
	}
	
	void addGroupReport(TestGroupReport report) {
		groupReports.add(report);
	}
	
	void computeSummary() {
		for (TestGroupReport report : groupReports) {
			totalPassed += report.getPassedCnt();
			totalFailed += report.getFailedCnt();
			totalSkipped += report.getSkippedCnt();
		}
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder("Test Suite Report - ");
		sb.append("total: ").append(getTotal()).append(", ");
		sb.append("passed: ").append(getTotalPassed()).append(", ");
		sb.append("failed: ").append(getTotalFailed()).append(", ");
		sb.append("skipped: ").append(getTotalSkipped());
		return sb.toString();
	}
}
