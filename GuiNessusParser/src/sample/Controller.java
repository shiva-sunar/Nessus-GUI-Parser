package sample;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;


public class Controller {
    @FXML
    private TextField browseText;
    @FXML
    private Button browseButton;
    @FXML
    private Button createButton;
    @FXML
    private Button helpButton;
    @FXML
    private CheckBox ipCheck, macCheck, netBiosCheck, naCheck;
    private List<File> files = null;

    public Controller() {
    }

    public void checkBoxClicked() {
        Vulnerability.showIP = ipCheck.isSelected();
        Vulnerability.showMAC = macCheck.isSelected();
        Vulnerability.showNetBios = netBiosCheck.isSelected();
        Vulnerability.showNA = naCheck.isSelected();
    }

    public void browseClicked(MouseEvent mouseEvent) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Nessus Files");
        chooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter[]
                {new FileChooser.ExtensionFilter("Nessus Files", new String[]{"*.nessus"})});
        List<File> tfiles = chooser.showOpenMultipleDialog(new Stage());
        files = tfiles;
        browseText.setText(files.toString());
    }

    public void createClicked(MouseEvent mouseEvent) {
        new Thread(() -> makeReports()).start();
    }

    private void makeReports() {
        if (files != null) {
            for (File file : files)
                makeReportForAFile(file);
        }
    }

    public void helpClicked(MouseEvent mouseEvent) throws Exception {
        System.out.println("Help Clicked.");
        Parent root = FXMLLoader.load(getClass().getResource("helpWindow.fxml"));
        Stage helpStage = new Stage();
        helpStage.setTitle("About GUI Parser");
        helpStage.setScene(new Scene(root));
        helpStage.setResizable(false);
        helpStage.getIcons().add(new Image(Main.class.getResourceAsStream("nessus.png")));
        helpStage.show();
    }

    public void makeReportForAFile(File file) {
        try {

//         write your code
            System.out.println(file.getAbsolutePath());
            System.out.println("================================");
            System.out.println("Nessus Parsing Started!!!");
            Nessus nessus = Nessus.GetNessus(file.getAbsolutePath());
//            System.out.println("Nessus Parsing Completed!!!");
//            System.out.println("================================");
//
//            System.out.println("================================");
//            System.out.println("Object Generation Started!!!");
            List<Vulnerability> vulnerabilities = Vulnerability.FromNessus(nessus);
            Collections.sort(vulnerabilities);
            List<Host> hosts = Host.getHostsWithVulnerabilities(vulnerabilities);
//            System.out.println("Object Generation Completed!!!");
//            System.out.println("================================");
//
//            System.out.println("================================");
//            System.out.println("Report String Generation Started!!!");
            String miniReport = Reporter.makeMiniReport(vulnerabilities, nessus.report.name);
            String detailedReport = Reporter.makeDetailedReport(vulnerabilities, nessus.report.name);
            String reportByHost = Reporter.makeReportByHosts(hosts, nessus.report.name);
//            System.out.println("Report String Generation Completed!!!");
//            System.out.println("================================");

            //----------------------------TEMP_CODE
//            for (Vulnerability v : vulnerabilities)
//                Vulnerability.Print(v);
            //-----------------------------TEMP_CODE

//            System.out.println("================================");
//            System.out.println("Report File Writing Started!!!");
            try {
                String justFileName = file.getName().substring(0, file.getName().lastIndexOf("."));
                String folder = file.getParent() + "\\" + justFileName;
                System.out.println(folder);
                Files.createDirectories(Paths.get(folder));
                PrintWriter mout = new PrintWriter(new FileOutputStream(folder + "\\" + justFileName + "MiniReport.html"));
                mout.println(miniReport);
                mout.flush();
                mout.close();
                PrintWriter dout = new PrintWriter(new FileOutputStream(folder + "\\" + justFileName + "DetailReport.html"));
                dout.println(detailedReport);
                dout.flush();
                dout.close();
                PrintWriter hout = new PrintWriter(new FileOutputStream(folder + "\\" + justFileName + "ReportByHost.html"));
                hout.println(reportByHost);
                hout.flush();
                hout.close();
                System.out.println("Report File Writing Completed!!!");
                System.out.println("================================");
                browseText.setText("Report Successfully Created!!!");

            } catch (Exception e) {
                System.out.println("There Was Some Error in Report Writing!!!");
                System.out.println("================================");
            }
        } catch (Exception e) {
            e.printStackTrace();
            browseText.setText("Report Creation Unsuccessful!!!");
        }
    }
}
