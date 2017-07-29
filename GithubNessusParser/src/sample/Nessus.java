package sample;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;
import java.io.File;
import java.io.StringWriter;
import java.util.List;

/**
 * Created by ShiPC on 1/15/2017.
 */

/**
 * This class converts a .nessus file exported from the Nessus Vulnerability Scanner,
 * which is an XML file, .nessus=.xml , to a java object of this class named Nessus.
 * so that it can be accessed easily and fast.
 * To see the details about the XML organization or architecture of .nessus file refer to
 * https://static.tenable.com/documentation/nessus_v2_file_format.pdf
 * Simple Structure is given below.
 * nessus
 *      Policy          we don't need this part.
 *          Policy Name
 *          List of Preferences
 *      Report(Name)
 *
 *
 *
 * */
@XmlRootElement(name = "NessusClientData_v2")
public class Nessus {
    @XmlElement(name = "Policy", type = Policy.class)
    public Policy policy;
    @XmlElement(name = "Report", type = Report.class)
    public Report report;

    public static Nessus GetNessus(String fileName) {
        try {
            File file = new File(fileName);
            if (!file.exists()) {
                System.out.println("File Doesn't Exits!!!");
                return null;
            }

            JAXBContext jaxbContext = JAXBContext.newInstance(Nessus.class);
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            Nessus nessus = (Nessus) jaxbUnmarshaller.unmarshal(file);
            return nessus;
        } catch (JAXBException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String DeserializeToXML(Nessus nessus){
        try {
            StringWriter writer = new StringWriter();
            JAXBContext context = JAXBContext.newInstance(Nessus.class);
            Marshaller m = context.createMarshaller();
            m.marshal(nessus, writer);
            return writer.toString();
        }catch (Exception e){System.out.println("Error in Deserializing Nesssus File");e.printStackTrace();}
        return "There was some Error in Deserializing Nessus File.";
    }

}

class Policy {
    @XmlElement(name = "policyName", type = String.class)
    public String policyName = "@@@NA";
    @XmlElement(name = "Preferences", type = Preferences.class)
    public Preferences preferences;

}

class Preferences {
    @XmlElement(name = "ServerPreferences", type = ServerPreferences.class)
    public ServerPreferences serverPreferences;
}

class ServerPreferences {
    @XmlElement(name = "preference")
    public List<preference> preferences;
}

class preference {
    @XmlElement(name = "name", type = String.class)
    public String name = "@@@NA";
    @XmlElement(name = "value", type = String.class)
    public String value = "@@@NA";
}


class Report {
    @XmlAttribute(name = "name")
    public String name = "@@@NA";
    @XmlElement(name = "ReportHost")
    public List<ReportHost> reportHosts;

}

class ReportHost {
    @XmlAttribute(name = "name")
    public String name = "@@@NA";
    @XmlElement(name = "HostProperties", type = HostProperties.class)
    public HostProperties hostProperties;
    @XmlElement(name = "ReportItem")
    public List<ReportItem> reportItems;

}

class HostProperties {
    @XmlElement(name = "tag")
    public List<Tag> tags;

    public String getTag(String tagName) {
        for (Tag t : tags)
            if (t.name.equals(tagName))
                return t.value;
        return "@@@NA";
    }
}

class Tag {
    @XmlAttribute(name = "name")
    public String name = "@@@NA";
    @XmlValue
    public String value = "@@@NA";
}

class ReportItem {
    @XmlAttribute(name = "port")
    public String port = "@@@NA";
    @XmlAttribute(name = "svc_name")
    public String svc_name = "@@@NA";
    @XmlAttribute(name = "protocol")
    public String protocol = "@@@NA";
    @XmlAttribute(name = "pluginID")
    public String pluginID = "@@@NA";
    @XmlAttribute(name = "pluginName")
    public String pluginName = "@@@NA";
    @XmlElement(name = "agent", type = String.class)
    public String agent = "@@@NA";
    @XmlElement(name = "description", type = String.class)
    public String description = "@@@NA";
    @XmlElement(name = "plugin_name", type = String.class)
    public String plugin_name = "@@@NA";
    @XmlElement(name = "risk_factor", type = String.class)
    public String riskFactor = "@@@NA";
    @XmlElement(name = "solution", type = String.class)
    public String solution = "@@@NA";
    @XmlElement(name = "synopsis", type = String.class)
    public String synopsis = "@@@NA";
    @XmlElement(name = "plugin_output", type = String.class)
    public String plugin_output = "@@@NA";
    @XmlElement(name = "cvss_temporal_score", type = String.class)
    public String cvssTemporalScore = "@@@NA";
    @XmlElement(name = "cvss_base_score", type = String.class)
    public String cvssBaseScore = "@@@NA";
}