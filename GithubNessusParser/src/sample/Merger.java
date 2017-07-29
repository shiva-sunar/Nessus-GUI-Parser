package sample;

import java.io.File;
import java.util.List;

/**
 * Created by ShiPC on 7/15/2017.
 */
public class Merger {
    public static Nessus MergeNessuss(List<File> fileList) {
        Nessus merged = Nessus.GetNessus(fileList.get(0).getAbsolutePath());
        merged.report.reportHosts.clear();
        for (File file : fileList) {
            Nessus current = Nessus.GetNessus(file.getAbsolutePath());
            merged = Merge(merged, current);
        }
        return merged;
    }

    private static Nessus Merge(Nessus a, Nessus b) {
        for (ReportHost bRH : b.report.reportHosts) {

//            if the host is not in the merged report then add it.
            if(!isRHinRHList(bRH,a.report.reportHosts))
                a.report.reportHosts.add(bRH);

//            if ReportHost is already in Merged Report then check for Report Items.
            else {
                for (ReportItem RIbRH:bRH.reportItems){
                    for(ReportHost aRH:a.report.reportHosts)
//                        checking same or equivalent host of bRH in a.ReportHosts.
                        if(aRH.name.equals(bRH.name)){
//                          if the reportItem was not in merged ReportHost then add it.
                            if(!isRIinRIList(RIbRH,aRH.reportItems))
                                aRH.reportItems.add(RIbRH);
                        }
                }
            }
        }
        return a;
    }
    private static boolean isRHinRHList(ReportHost rh,List<ReportHost>rhList) {
        for (ReportHost a:rhList)
            if(rh.name.equals(a.name))
                return true;
        return false;
    }
    private static boolean isRIinRIList(ReportItem ri,List<ReportItem>riList) {
        for (ReportItem a:riList)
//            use pluginName NOT plugin_name
            if(a.pluginName.equals(ri.pluginName))
                return true;
        return false;
    }
    static void print(String a){
        System.out.println(a);
    }
}
