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
    private Button mergeButton;
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
            new Thread(() -> Updater.updateApplication(Main.version)).start();
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
        if (files != null)
            browseText.setText(files.toString());
    }


    public void createClicked(MouseEvent mouseEvent) {
        new Thread(() -> makeReports()).start();
    }

    public void mergeClicked(MouseEvent mouseEvent) {
        new Thread(() -> mergeNessus()).start();
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

    public void gotoGitHub() {

    }

    private void mergeNessus() {

        if (files != null) {
            Nessus mergedNessus = Merger.MergeNessuss(files);
            String deserialized = Nessus.DeserializeToXML(mergedNessus);
            if (new File(files.get(0).getParent() + "\\Merged").mkdir()) {
                writeAFile(deserialized, files.get(0).getParent() + "\\Merged\\Merged.nessus");
                browseText.setText("Files Merged!!!");
            } else browseText.setText("Couldn't Create Folder");
        }
    }


    private void makeReports() {
        if (files != null) {
            for (File file : files)
                makeReportForAFile(file);
        }
    }

    private void makeReportForAFile(File file) {
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

            String justFileName = file.getName().substring(0, file.getName().lastIndexOf("."));
            String folder = file.getParent() + "\\" + justFileName;
            Files.createDirectories(Paths.get(folder));
            boolean isFileWritten = true;
            isFileWritten = isFileWritten &&
                    writeAFile(miniReport, folder + "\\" + justFileName + "MiniReport.html") &&
                    writeAFile(detailedReport, folder + "\\" + justFileName + "DetailedReport.html") &&
                    writeAFile(reportByHost, folder + "\\" + justFileName + "ReportByHost.html");
            if (isFileWritten) browseText.setText("Report Successfully Created!!!");
            else browseText.setText("Some Error in Writing File!!!");
//
        } catch (Exception e) {
            e.printStackTrace();
            browseText.setText("Report Creation Unsuccessful!!!\nSee StackTrace!!!");
        }
    }

    private boolean writeAFile(String content, String filename) {
        try {
            PrintWriter printWriter = new PrintWriter(new FileOutputStream(filename));
            printWriter.println(content);
            printWriter.flush();
            printWriter.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            browseText.setText("Some Error in Writing File!!!");
            return false;
        }
    }
}
