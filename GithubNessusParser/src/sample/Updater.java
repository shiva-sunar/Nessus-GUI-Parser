package sample;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.stream.Collectors;

/**
 * Created by ShiPC on 7/17/2017.
 */
public class Updater {
    public static boolean isUpdateChecked=false;
    private static String latestVersion="";

    public static boolean updateApplication(String version) {
        if (isUpdateAvailable(version)) {
            String jarURL = "https://github.com/thinkshiva7/Nessus-GUI-Parser/raw/master/Nessus.Parser.v"+latestVersion+".jar";
            String pwd = Paths.get(".").toAbsolutePath().normalize().toString();
            print("Downloading Update!!!");
            if(download(jarURL, pwd)) {
                print("Update Downloaded in current folder " + pwd + " !!!");
                return true;
            }
        }
        return false;
    }

    private static boolean isUpdateAvailable(String version) {
        try {
            URL u = new URL("https://raw.githubusercontent.com/thinkshiva7/Nessus-GUI-Parser/master/Older%20Versions/latestVersion.txt");
            print("Checking Updates!!!");
            InputStream in = u.openStream();
            String result = new BufferedReader(new InputStreamReader(in))
                    .lines().collect(Collectors.joining("\n"));
            if (!result.equals(version)) {
                print("Update is Available!!!\nNessus.Report.Generator.v"+result);
                latestVersion=result.trim();
                return true;
            }
        } catch (Exception e) {
            print("Some Error Occurred  While Checking Update");
            e.printStackTrace();
            return false;
        }
        print("Application is Latest, Update Not Available!!!");
        return false;
    }

    private static boolean download(String sourceURL, String targetDirectory) {
        try {
            URL url = new URL(sourceURL);
            String fileName = sourceURL.substring(sourceURL.lastIndexOf('/') + 1, sourceURL.length());
            Path targetPath = new File(targetDirectory + File.separator + fileName).toPath();
//            print("Downloading " + sourceURL + " to " + targetDirectory);
            Files.copy(url.openStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);
//            print(sourceURL + " was downloaded to " + targetDirectory);
            return true;
        } catch (Exception e) {
            print("Unable to download " + sourceURL + " in " + targetDirectory);
            e.printStackTrace();
        }
        return false;
    }

    static void print(Object a) {
        System.out.println(a);
    }
}
