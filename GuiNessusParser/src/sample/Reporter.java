package sample;

import java.util.List;

/**
 * Created by ShiPC on 1/25/2017.
 */
public class Reporter {
    private static final String miniReportBody = fixedStrings.miniReportBody;
    private static final String miniTableRow = fixedStrings.miniTableRow;
    private static final String detailReportBody = fixedStrings.detailReportBody;
    private static final String detailTableRow = fixedStrings.detailTableRow;
    private static final String reportByHostBody = fixedStrings.reportByHostBody;
    private static final String reportByHostTable = fixedStrings.reportByHostTable;
    private static final String reportByHostTableVulnerability = fixedStrings.reportByHostTableVulnerability;

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
            hostTable=hostTable.replace("@@@IPAddress",host.IP);
            String rows = "";
            for (Vulnerability v : host.vulnerabilitiesInHost) {
                String vulnRow = fixedStrings.reportByHostTableVulnerability;
                vulnRow = vulnRow.replace("@@@Vulnerability", v.pluginName);
                vulnRow = vulnRow.replace("@@@Criticality", v.riskFactor);
                vulnRow = vulnRow.replace("@@@Solution", v.solution);
                vulnRow=vulnRow.replace("@@@Color",color(v));
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

    class fixedStrings {
        public static final String miniReportBody = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "\t<title>@@@ReportTitle</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "\t<style type=\"text/css\">\n" +
                "\t\t.detable  {" +
                "border-collapse:collapse;" +
                "border-spacing:0;" +
                "border-color:#999;" +
                "font-family:Verdana,sans-serif;font-size:13px;" +
                "}\n" +
                "\t\t.detable td{" +
                "\t\t\t\tpadding:4px 20px;" +
                "\t\t\t\tborder-style:solid;" +
                "\t\t\t\tborder-width:1px;" +
                "\t\t\t\toverflow:hidden;" +
                "\t\t\t\tword-break:normal;" +
                "\t\t\t\tborder-color:#999;" +
                "\t\t\t\tcolor:#444;" +
                "\t\t\t\tbackground-color:#F7FDFA;" +
                "}\n" +
                "\t\t.detable th{font-weight:normal;" +
                "\t\t\t\tpadding:4px 20px;" +
                "\t\t\t\tborder-style:solid;" +
                "\t\t\t\tborder-width:1px;" +
                "\t\t\t\toverflow:hidden;" +
                "\t\t\t\tword-break:normal;" +
                "\t\t\t\tborder-color:#999;" +
                "\t\t\t\tcolor:#000;" +
                "\t\t\t\tbackground-color:#fff;" +
                "}\n" +
                "\t\t.detable .colorfuls{" +
                "\t\t\t\tfont-weight:bold;" +
                "\t\t\t\ttext-align: center;" +
                "\t\t\t\tvertical-align:center;" +
                "}\n" +
                "\t\t.detable .tableHeader{" +
                "\t\t\t\tfont-weight:bold;" +
                "\t\t\t\tbackground-color:#b3d9ff;" +
                "\t\t\t\tvertical-align:top;" +
                "\t\t\t\ttext-align: center;" +
                "}\n" +
                "\t\t.detable .remarks{" +
                "\t\t\t\tvertical-align:top;" +
                "\t\t\t\ttext-align: left;" +
                "}\n" +
                "\t\t.detable .vulName{" +
                "\t\t\t\ttext-align: left;" +
                "\t\t\t\tvertical-align:top;" +
                "\t\t\t\tfont-weight: bold;" +
                "}\n" +
                "\t</style>\n" +
                "\t<table class=\"detable\">\n" +
                "\t\t<tr>\n" +
                "\t\t\t<th class=\"tableHeader\">Vulnerability</th>\n" +
                "\t\t\t<th class=\"tableHeader\">Criticality</th>\n" +
                "\t\t\t<th class=\"tableHeader\">Impact on Business</th>\n" +
                "\t\t\t<th class=\"tableHeader\">Remarks</th>\n" +
                "\t\t</tr>\n" +
                "\n" +
                "\t\t@@@MiniReportRows\n" +
                "\n" +
                "\t\t</table>\n" +
                "</body>\n" +
                "</html>";
        public static final String miniTableRow = "\n" +
                "\t\t<tr>\n" +
                "\t\t\t<th class=\"vulName\">@@@VulnerabilityName</th>\n" +
                "\t\t\t<th class=\"colorfuls\"><font color=\"@@@Color\">@@@CriticalityStars</font></th>\n" +
                "\t\t\t<th class=\"colorfuls\"><font color=\"@@@Color\">@@@RiskFactor</font></th>\n" +
                "\t\t\t<th class=\"remarks\">@@@Remarks</th>\n" +
                "\t\t</tr>\n" +
                "\t\t<tr>\n" +
                "\t\t\t<td class=\"remarks\" colspan=\"4\">@@@IPs</td>\n" +
                "\t\t</tr>\n" +
                "<!-- ----------------------------------------------------------------------------------------------------------------------------------------- -->" +
                "\n";
        public static final String detailReportBody = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "\n" +
                "<head>\n" +
                "\t<title>@@@ReportTitle</title>\n" +
                "\t<style type=\"text/css\">\n" +
                "\t\t.tg {\n" +
                "\t\t\tborder-collapse: collapse;\n" +
                "\t\t\tborder-spacing: 0;\n" +
                "\t\t}\n" +
                "\t\t.tg td {\n" +
                "\t\t\tfont-family: Verdana, sans-serif;\n" +
                "\t\t\tfont-size: 13px;\n" +
                "\t\t\tpadding: 5px 10px;\n" +
                "\t\t\tborder-style: solid;\n" +
                "\t\t\tborder-width: 1px;\n" +
                "\t\t\toverflow: hidden;\n" +
                "\t\t\tword-break: normal;\n" +
                "\t\t}\n" +
                "\t\t.tg .ipTitle {\n" +
                "\t\t\tfont-weight: bold;\n" +
                "\t\t\tbackground-color: #80aaff;\n" +
                "\t\t\tvertical-align: top;\n" +
                "\t\t\tborder: 3px solid black;\n" +
                "\t\t\tfont-weight: bold;\n" +
                "\t\t\tborder-style: solid;\n" +
                "\t\t\toverflow: hidden;\n" +
                "\t\t\tword-break: normal;\n" +
                "\t\t\ttext-align: center;\n" +
                "\t\t}\n" +
                "\t\t.tg .ipAddress {\n" +
                "\t\t\tvertical-align: top;\n" +
                "\t\t\ttext-align: center;\n" +
                "\t\t}\n" +
                "\t\t.blockTitle {\n" +
                "\t\t\tpadding: 5px;\n" +
                "\t\t\tfont-weight: bold;\n" +
                "\t\t\tbackground-color: #f2f2f2;\n" +
                "\t\t}\n" +
                "\t\t.blockDescription {\n" +
                "\t\t\tpadding: 5px;\n" +
                "\t\t\ttext-align: justify;\n" +
                "\t\t\tmargin-bottom: 15px;\n" +
                "\t\t}\n" +
                "\t</style>\n" +
                "</head>\n" +
                "\n" +
                "<body style=\"font-family:Verdana,sans-serif; font-size: 13px;\">\n" +
                "\n" +
                "@@@DetailReportTable" +
                "\n" +
                "</body>\n" +
                "\n" +
                "</html>";
        public static final String detailTableRow = "\n" +
                "\n" +
                "\n" +
                "\t<p style=\"font-weight:bold;\">@@@newLineVulnerability Name: @@@VulnerabilityName</p>\n" +
                "\t<p style=\"font-weight:bold;\">Risk: <span style=\"color:@@@Color\">@@@Stars</span>\n" +
                "\t</p>\n" +
                "\t<p style=\"font-weight:bold;\">Impact on Business: @@@RiskFactor</p>\n" +
                "\t<p>\n" +
                "\t\t<strong>Description: </strong> @@@Synopsis\n" +
                "\t</p>\n" +
                "\t<p>\n" +
                "\t\t<span style=\"color:#1a1aff;font-weight:bold;\">Solution:</span> Apply solutions as per described in table below.\n" +
                "\t</p>\n" +
                "\t<table class=\"tg\">\n" +
                "\t\t<tr>\n" +
                "\t\t\t<td class=\"ipTitle\">IP Address</td>\n" +
                "\t\t</tr>\n" +
                "\t\t<tr>\n" +
                "\t\t\t<td class=\"ipAddress\">@@@IP</td>\n" +
                "\t\t</tr>\n" +
                "\t\t<tr>\n" +
                "\t\t\t<td>\n" +
                "\t\t\t\t<div style=\"background-color:@@@Color;font-weight:bold;padding:7px; color:white;font-size:16px;\">\n" +
                "\t\t\t\t\t@@@VulnerabilityName\n" +
                "\t\t\t\t</div>\n" +
                "\t\t\t\t<div class=\"blockTitle\">\n" +
                "\t\t\t\t\t<br/>Synopsis</div>\n" +
                "\t\t\t\t<div class=\"blockDescription\">\n" +
                "\t\t\t\t\t@@@Synopsis\n" +
                "\t\t\t\t\t<br/>\n" +
                "\t\t\t\t\t<br/> </div>\n" +
                "\t\t\t\t<div class=\"blockTitle\">Description</div>\n" +
                "\t\t\t\t<div class=\"blockDescription\">\n" +
                "\t\t\t\t\t@@@Description\n" +
                "\t\t\t\t\t<br/>\n" +
                "\t\t\t\t\t<br/> \n" +
                "\t\t\t\t</div>\n" +
                "\t\t\t\t<div class=\"blockTitle\">Solution</div>\n" +
                "\t\t\t\t<div class=\"blockDescription\">\n" +
                "\t\t\t\t\t@@@Solution\n" +
                "\t\t\t\t\t<br/>\n" +
                "\t\t\t\t\t<br/>\n" +
                "\t\t\t\t</div>\n" +
                "\t\t\t\t<div class=\"blockTitle\">Risk Factor</div>\n" +
                "\t\t\t\t<div class=\"blockDescription\">\n" +
                "\t\t\t\t\t@@@RiskFactor\n" +
                "\t\t\t\t\t<br/>\n" +
                "\t\t\t\t</div>\n" +
                "\t\t\t</td>\n" +
                "\t\t</tr>\n" +
                "\t</table>\n" +
                "\n" +
                "<!-- ----------------------------------------------------------------------------------------------------------------------------------------- -->" +
                "\n" +
                "\n";
        public static final String reportByHostBody = "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "  <title>@@@ReportTitle</title>\n" +
                "</head>\n" +
                "<style type=\"text/css\">\n" +
                "  .table  {border-collapse:collapse;border-spacing:0;border-color:#999;border-width: 20px;}\n" +
                "  .table td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#999;color:#444;background-color:#F7FDFA;}\n" +
                "  .table th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#999;color:#fff;background-color:#26ADE4;}\n" +
                "  .table .table-IPAddress{font-weight:bold;font-size:13px;font-family:Verdana, Geneva, sans-serif ;background-color:#c0cdf6;color:#000000;text-align:center;vertical-align:middle;}\n" +
                "  .table .table-Vulnerability{font-weight:bold;font-size:13px;font-family:Verdana, Geneva, sans-serif ;background-color:#efefef;vertical-align:middle;}\n" +
                "  .table .table-Heading{font-weight:bold;font-size:13px;font-family:Verdana, Geneva, sans-serif ;background-color:#080874;color:#efefef;text-align:center;vertical-align:middle;}\n" +
                "  .table .table-Criticality{font-weight:bold;font-size:13px;font-family:Verdana, Geneva, sans-serif ;background-color:#efefef;text-align:center;vertical-align:middle;}\n" +
                "  .table .table-Solution{font-size:13px;font-family:Verdana, Geneva, sans-serif ;background-color:#efefef;vertical-align:middle;}\n" +
                "</style>\n" +
                "<body style=\"vertical-align: middle;\">" +
                "@@@ReportByHostTables" +
                "</body>\n" +
                "</html>";
        public static final String reportByHostTable = "  <table class=\"table\">\n" +
                "    <tr>\n" +
                "      <th class=\"table-IPAddress\" colspan=\"3\">@@@IPAddress</th>\n" +
                "    </tr>\n" +
                "    <tr>\n" +
                "      <td width=\"40%\" class=\"table-Heading\">Vulnerability</td>\n" +
                "      <td width=\"5%\" class=\"table-Heading\">Criticality</td>\n" +
                "      <td width=\"55%\" class=\"table-Heading\">Solution</td>\n" +
                "    </tr>" +
                "@@@ReportByHostTableVulnerability" +
                "  </table>";
        public static final String reportByHostTableVulnerability = "<tr>\n" +
                "      <td class=\"table-Vulnerability\">@@@Vulnerability</td>\n" +
                "      <td class=\"table-Criticality\" style=\"color: @@@Color;\">@@@Criticality</td>\n" +
                "      <td class=\"table-Solution\">@@@Solution</td>\n" +
                "    </tr>";

    }
}



