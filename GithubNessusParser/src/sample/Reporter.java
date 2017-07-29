package sample;

import java.util.List;
import java.util.Scanner;

/**
 * Created by ShiPC on 1/25/2017.
 */
public class Reporter {
    private static final String miniReportBody = getFixedStaticString("html/miniReportBody.html");
    private static final String miniTableRow = getFixedStaticString("html/miniTableRow.html");
    private static final String detailReportBody = getFixedStaticString("html/detailReportBody.html");
    private static final String detailTableRow = getFixedStaticString("html/detailTableRow.html");
    private static final String reportByHostBody = getFixedStaticString("html/reportByHostBody.html");
    private static final String reportByHostTable = getFixedStaticString("html/reportByHostTable.html");
    private static final String reportByHostTableVulnerability = getFixedStaticString("html/reportByHostTableVulnerability.html");

    public static String makeMiniReport(List<Vulnerability> vulnerabilityList) {
        return makeMiniReport(vulnerabilityList, "");
    }

    public static String makeMiniReport(List<Vulnerability> vulnerabilityList, String reportName) {
        String miniReport = miniReportBody.replace("@@@ReportTitle", "MR: " + reportName);
        String rows = "";
        for (Vulnerability v : vulnerabilityList) {
            String row = miniTableRow;
            row = row.replace("@@@VulnerabilityName", v.pluginName);
            row = row.replace("@@@CriticalityStars", stars(v));
            row = row.replace("@@@Color", color(v));
            row = row.replace("@@@RiskFactor", v.riskFactor);
            row = row.replace("@@@Remarks", v.solution);
            row = row.replace("@@@IPs", v.IPs.toString().replace("[", "").replace("]", ""));
            rows = rows + row;
        }
        miniReport = miniReport.replace("@@@MiniReportRows", rows);
        return miniReport;
    }


    public static String makeDetailedReport(List<Vulnerability> vulnerabilityList) {
        return makeDetailedReport(vulnerabilityList, "");
    }

    public static String makeDetailedReport(List<Vulnerability> vulnerabilityList, String reportName) {
        String detailedReport = detailReportBody;
        detailedReport = detailedReport.replace("@@@ReportTitle", "DR: " + reportName);
        String rows = "";
        for (Vulnerability v : vulnerabilityList) {
            String row = detailTableRow;
            row = row.replace("@@@VulnerabilityName", v.pluginName);
            row = row.replace("@@@RiskFactor", v.riskFactor);
            row = row.replace("@@@Stars", stars(v));
            row = row.replace("@@@Color", color(v));
            row = row.replace("@@@Synopsis", v.synopsis);
            row = row.replace("@@@Solution", v.solution);
            row = row.replace("@@@Description", v.description);
            row = row.replace("@@@IP", v.IPs.get(0));
            rows = rows + row;
        }
        detailedReport = detailedReport.replace("@@@DetailReportTable", rows);
        return detailedReport;
    }


    public static String makeReportByHosts(List<Host> hostList) {
        return makeReportByHosts(hostList, "");
    }

    public static String makeReportByHosts(List<Host> hostList, String reportName) {
        String reportByHosts = reportByHostBody;
        reportByHosts = reportByHosts.replace("@@@ReportTitle", "RbH: " + reportName);
        String allHostTables = "";
        for (Host host : hostList) {
            String hostTable = reportByHostTable;
            hostTable = hostTable.replace("@@@IPAddress", host.IP);
            String rows = "";
            for (Vulnerability v : host.vulnerabilitiesInHost) {
                String vulnRow = reportByHostTableVulnerability;
                vulnRow = vulnRow.replace("@@@Vulnerability", v.pluginName);
                vulnRow = vulnRow.replace("@@@Criticality", v.riskFactor);
                vulnRow = vulnRow.replace("@@@Solution", v.solution);
                vulnRow = vulnRow.replace("@@@Color", color(v));
                rows += vulnRow;
            }
            hostTable = hostTable.replace("@@@ReportByHostTableVulnerability", rows);
            allHostTables += hostTable + "<p>@@@newLine</p>";
        }
        reportByHosts = reportByHosts.replace("@@@ReportByHostTables", allHostTables);
        return reportByHosts;
    }

    private static String stars(Vulnerability v) {
        if (v.riskFactor.equals("Critical")) return "* * * * *";
        if (v.riskFactor.equals("High")) return "* * * *";
        if (v.riskFactor.equals("Medium")) return "* * *";
        if (v.riskFactor.equals("Low")) return "* *";
        return "@@@NoStars";
    }

    private static String color(Vulnerability v) {
        if (v.riskFactor.equals("Critical")) return "#C00000";
        if (v.riskFactor.equals("High")) return "#FF0000";
        if (v.riskFactor.equals("Medium")) return "#ED7D31";
        if (v.riskFactor.equals("Low")) return "#00B050";
        return "@@@NoColor";
    }

    public static String getFixedStaticString(String path) {
        try {
            String text = new Scanner(Reporter.class.getResourceAsStream(path), "UTF-8").useDelimiter("\\A").next();
            return text;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

}
