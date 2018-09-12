import java.io.*;
import java.util.*;


public class firewall {


    private HashMap<String,HashMap<String,String>> maps = new HashMap<>();
    public firewall(String csvFile){

        BufferedReader br = null;
        try {

            //to read the rules csv
            br = new BufferedReader(new FileReader(csvFile));
            String line = "";
            String separator = ",";
            while ((line = br.readLine()) != null) {


                String[] rule = line.split(separator);
                //System.out.println("direction"+rule[3]);

                //traversing row by row and placing the contents in initial 4 variables
                String direction = rule[0];
                String protocol = rule[1];
                String port_range = rule[2];
                String ip_range = rule[3];
                HashMap<String,String> direction_prot;

                //if both IP address and port number are single values
                if(!ip_range.contains("-") && !port_range.contains("-")){

                    direction_prot = new HashMap<String,String>();
                    direction_prot.put(protocol, direction);
                    String combo = ip_range+":"+port_range;
                    maps.put(combo, direction_prot);
                }

                //if both IP address and port numbers are ranges given
                else if(ip_range.contains("-") && port_range.contains("-")){

                    String ip1=ip_range.split("-")[0];
                    String ip2=ip_range.split("-")[1];
                    String[] ip1_contents = ip1.split("\\.");
                    long low = (long)(Double.parseDouble(ip1_contents[3])*Math.pow(256,0)+Double.parseDouble(ip1_contents[2])*Math.pow(256,1)+Double.parseDouble(ip1_contents[1])*Math.pow(256,2)+Double.parseDouble(ip1_contents[0])*Math.pow(256,3));

                    String[] ip2_contents = ip2.split("\\.");
                    long high = (long) (Double.parseDouble(ip2_contents[3])*Math.pow(256,0)+Double.parseDouble(ip2_contents[2])*Math.pow(256,1)+Double.parseDouble(ip2_contents[1])*Math.pow(256,2)+Double.parseDouble(ip2_contents[0])*Math.pow(256,3));

                    //System.out.println(low +" " + high);

                    //Generate the list of IPs between the given range(including the ends).
                    // Using base 256 logic
                    for(long i=low;i<=high;i++){
                        List<String> sb = new ArrayList<>();
                        long current = i;
                        int c = 4;
                        while(current>0){
                            sb.add(0,current%256+".");
                            current = current/256;
                            c--;
                        }
                        while(c>0) {
                            sb.add(0, 0 + ".");
                            c--;
                        }

                        StringBuilder ip0 = new StringBuilder();
                        for(int j=0;j<sb.size();j++) {
                            ip0.append(sb.get(j));
                        }
                        String ip = ip0.toString().substring(0,ip0.length()-1);
                        Long lowPort = Long.parseLong(port_range.split("-")[0]);
                        Long highPort = Long.parseLong(port_range.split("-")[1]);


                        //generate all combinations of IP address and port and add to main Hashmap
                        for(Long j=lowPort; j<=highPort;j++)
                        {
                            direction_prot = new HashMap<String,String>();
                            direction_prot.put(protocol, direction);
                            maps.put(ip +":" +String.valueOf(j), direction_prot);
                        }

                    }

                }

                //IP address is range and port is single value
                else if(ip_range.contains("-") && !port_range.contains("-")){
                    String ip1=ip_range.split("-")[0];
                    String ip2=ip_range.split("-")[1];
                    String[] ip1_contents = ip1.split("\\.");
                    long low = (long)(Double.parseDouble(ip1_contents[3])*Math.pow(256,0)+Double.parseDouble(ip1_contents[2])*Math.pow(256,1)+Double.parseDouble(ip1_contents[1])*Math.pow(256,2)+Double.parseDouble(ip1_contents[0])*Math.pow(256,3));

                    String[] ip2_contents = ip2.split("\\.");
                    long high = (long) (Double.parseDouble(ip2_contents[3])*Math.pow(256,0)+Double.parseDouble(ip2_contents[2])*Math.pow(256,1)+Double.parseDouble(ip2_contents[1])*Math.pow(256,2)+Double.parseDouble(ip2_contents[0])*Math.pow(256,3));

                    //System.out.println(low +" " + high);

                    //Generate the list of IPs between the given range(including the ends)
                    for(long i=low;i<=high;i++) {
                        List<String> sb = new ArrayList<>();
                        long current = i;
                        int count = 4;
                        while (current > 0) {
                            sb.add(0, current % 256 + ".");
                            current = current / 256;
                            count--;
                        }
                        while (count > 0) {
                            sb.add(0, 0 + ".");
                            count--;
                        }

                        StringBuilder ip0 = new StringBuilder();
                        for (int j = 0; j < sb.size(); j++) {
                            ip0.append(sb.get(j));
                        }
                        String ip = ip0.toString().substring(0, ip0.length() - 1);
                        direction_prot = new HashMap<String,String>();
                        direction_prot.put(protocol, direction);
                        maps.put(ip+":"+String.valueOf(port_range),direction_prot);

                    }

                }

                //IP address is single value and port is range given
                else if(!ip_range.contains("-") && port_range.contains("-")) {

                    Long lowPort = Long.parseLong(port_range.split("-")[0]);
                    Long highPort = Long.parseLong(port_range.split("-")[1]);


                    for(Long j=lowPort; j<=highPort;j++)
                    {
                        direction_prot = new HashMap<String,String>();
                        direction_prot.put(protocol, direction);
                        maps.put(ip_range +":" +String.valueOf(j), direction_prot);
                    }
                }

                //System.out.println(maps);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    //verify if the packet is allowed based on the rules
    boolean accept_packet(String direction, String protocol, Integer port, String ip_address){

        String k1 = ip_address +":"+ port;
        String k2  = protocol;

        //easy retrieval
        // Just check the accept packet function against the keys created from the combinations
        if(maps.containsKey(k1)) {
            HashMap<String,String> temp = maps.get(k1);
            if(temp.containsKey(k2) && temp.get(k2).equals(direction)){
                return true;
            }
        }

        return false;
    }


    public static void main(String[] args) {

        String csvFile = "/Users/aditya16.narula/IdeaProjects/p1/Illumio_Aditya/rules.csv";
        firewall fw  = new firewall(csvFile);


        String input_file = "/Users/aditya16.narula/IdeaProjects/p1/Illumio_Aditya/packets.csv";
        BufferedReader br = null;

        try {

            br = new BufferedReader(new FileReader(input_file));
            String line = "";
            String separator = ",";
            boolean result;
            while ((line = br.readLine()) != null) {
                String[] packet = line.split(separator);

                //traversing input file row by row and placing the contents in initial 4 variables
                String direction = packet[0];
                String protocol = packet[1];
                int port = Integer.parseInt(packet[2]);
                String ip_address = packet[3];

                // call the accept_packet function for each input packet
                result = fw.accept_packet(direction,protocol,port,ip_address);
                System.out.println(result);

            }

        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
