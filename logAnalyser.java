import java.io.File;
import java.io.FileNotFoundException;

import java.util.*;

public class logAnalyser {
    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);  // initialising the scanner
        String fileName = ""; // setting the filename
        while (fileName.isEmpty()){ // encouraging the user to enter a correct file name
            System.out.println("Enter the filename");
            fileName = scanner.nextLine();  // getting the file name
        }
        
        
        Integer type = 1; // initialising the variable 'type' to choose a function of the program
        ArrayList<String> Answer = new ArrayList<>(Arrays.asList("")); // initialising the 'Answer' array
        ArrayList fileLines = ReadFile(fileName); // returns the lines from the chosen file in an array
        while (type != 5) {
            System.out.println("What would you like to do?"); // giving the user options to choose from 
            System.out.println("1. Search for entries with a specific tag");
            System.out.println("2. Search for entries with a specific severity");
            System.out.println("3. Search for a specific message");
            System.out.println("4. Scan for any logs with select IP addresses");
            System.out.println("5. Exit");
            try{ // input validation try catch loop to ensure the user enters a number
                type = Integer.valueOf(scanner.nextLine()); 
            } catch (Exception e) {
                System.out.println("This is not a valid input");
                type = 6;
            }
                

            Integer otherChoice = 0; // initialising the variable 'other choice' to decide the type of answer
            if (type < 5 && type > 0){ // if the user has chosen an option that is not exit it asks further questions
                System.out.println("Would you like 1. a short answer, 2. an in depth answer, 3. just the date and time or 4. the client's IP addresses?");
                try{ // input validation try catch loop to ensure the user enters a number
                    otherChoice = Integer.valueOf(scanner.nextLine());
                } catch (Exception e) {
                    System.out.println("This is not a valid input");
                    otherChoice = 6;
                }
            }
            
            OUTER:
            switch (type) {
                case 1:
                {
                    System.out.println("Please enter the tag you would like to search for, or press enter for a list of specific options."); // prompting the user to enter any tags they would like
                    String theSearch = scanner.nextLine(); // getting the search variable
                    
                    if (!theSearch.isEmpty()){ // if they have input anything to be searched
                        Answer = tagReturn(fileLines, theSearch, "tag"); // returning all the lines with the tag in
                        switch (otherChoice) {
                            case 1:
                                ShortAnswer(Answer); // giving the user a short answer
                                break;
                            case 2:
                                LongAnswer(Answer); // giving the user a long answer
                                break;
                            case 3:
                                dateTime(Answer); // giving the user an answer with just the date and time of the incident
                                break;
                            default:
                                IPAddress(Answer); // giving the user an answer with just the IP addresses of the tag
                                break;
                        }
                        
                    }else {
                        System.out.println("Possible tags that could be used:"); // printing out possible tags the user could try
                        System.out.println("Paranoia");
                        System.out.println("OWASP");
                        System.out.println("Attack");
                        System.out.println("Language");
                    }       break;
                }
                case 2:
                    Integer choice = 0;
                    System.out.println("Would you like to search for 1. Critical Severity or 2. Warning severity?");
                    try{ // input validation for the choice variable
                        choice = Integer.valueOf(scanner.nextLine());
                    } catch (Exception e) {
                        System.out.println("This is not a valid input");
                        
                    }
                    switch (choice) { // running different return statements dependent on the choice
                        case 1:
                            Answer = tagReturn(fileLines, "CRITICAL", "severity");
                            switch (otherChoice) { // giving the users different levels of detail dependent on their choice
                                case 1:
                                    ShortAnswer(Answer);
                                    break;
                                case 2:
                                    LongAnswer(Answer);
                                    break;
                                case 3:
                                    dateTime(Answer);
                                default:
                                    IPAddress(Answer);
                                    break;
                            }           break OUTER; // breaking to outside of both switch case statments
                        case 2:
                            Answer = tagReturn(fileLines, "WARNING", "severity");
                            switch (otherChoice) {
                                case 1:
                                    ShortAnswer(Answer);
                                    break;
                                case 2:
                                    LongAnswer(Answer);
                                    break;
                                case 3:
                                    dateTime(Answer);
                                default:
                                    IPAddress(Answer);
                                    break;
                            }           break OUTER;
                        default:
                            System.out.println("This was not a valid input, please try again");
                            break;
                    }
                case 3:
                { // Asking the user the specific type of message they would like to search for
                    System.out.println("Please enter the message you would like to search for, or press enter for a list of specific options.");
                    String theSearch = scanner.nextLine();
                    if (theSearch.isEmpty()) { // giving the user a list of possible messages to search for
                        System.out.println("Possible message list");
                        System.out.println("Access Attempt");
                        System.out.println("Conflict");
                        System.out.println("Illegal");
                    }else if (!theSearch.isEmpty()){
                        Answer = tagReturn(fileLines, theSearch, "msg");
                        switch (otherChoice) { // giving the user the different choices for the length of response
                            case 1:
                                ShortAnswer(Answer);
                                break;
                            case 2:
                                LongAnswer(Answer);
                                break;
                            case 3:
                                dateTime(Answer);
                                break;
                            default:
                                IPAddress(Answer);
                                break;
                        }
                    } else {
                        break;
                    }
                    break;
                    
                }
                case 4:
                {
                    ArrayList IPS = ReadFile("ips.txt"); // reading the file 'ips.txt'
                    System.out.println("Matching safe IPs to the log file and printing out any anomalies.");
                    Answer = CheckIPs(fileLines, IPS); // running the function to check the safe IPs against the log file
                    switch (otherChoice) { // giving the user different options for the length of response 
                        case 1:
                            ShortAnswer(Answer);
                            break;
                        case 2:
                            LongAnswer(Answer);
                            break;
                        case 3:
                            dateTime(Answer);
                            break;
                        default:
                            IPAddress(Answer);
                            break;
                    }
                }
                case 5: // if the user wants to exit the program
                {
                    break;
                }
            }
        }
        scanner.close(); // closing the scanner
    }

    public static ArrayList ReadFile(String fileName) { 
        ArrayList<String> lineReturn = new ArrayList<String>(Arrays.asList("")); // creating a new array for the file lines
        try { // if the file can be found
            File file = new File(fileName); // opening the file
            Scanner myReader = new Scanner(file); // scanning the file
            while (myReader.hasNextLine()) { // while there is a line that has not been read
                String data = myReader.nextLine(); // adding this line to a variable
                lineReturn.add(data); // writing that variable to the array
            }
            myReader.close(); // closing the reader
        } catch (FileNotFoundException e) { // if the file does not exist
            System.out.println("An error occured"); // print out error message
        }
        return lineReturn; // return the array
    }

    public static void LongAnswer(ArrayList Answer) { // returning the array in a more readable format
        for (Object data : Answer) { // for each item in the array
            String[] parts = ((String) data).split("\\]"); // split the line into parts from their square brackets
            for (String part : parts) { // for each part within this split up part (Some parts of the logs do not have square brackets)
                String[] newpart = part.split("\\["); // split each new part by the open square bracket
                for (String newnewpart : newpart) { // for each part within this new string
                    if (newnewpart.equals(" ")){ // if it equals an empty space do nothing

                    } else {
                        System.out.println(newnewpart); // print out each part
                    }   
                }
            }
        }
    }

    public static void ShortAnswer(ArrayList Answer) { // returning the array in a more readable format with only important parts of the data
        for (Object data : Answer) { // spliting up the entries into strings of the individual bits
            String[] parts = ((String) data).split("\\]");
            for (String part : parts) {
                String[] newpart = part.split("\\["); 
                for (String newnewpart : newpart) {
                    if (newnewpart.contains("tag")){ // if the part includes any of the important messages it gets printed out
                        System.out.println(newnewpart);
                    } else if (newnewpart.contains("msg")){
                        System.out.println(newnewpart);
                    } else if (newnewpart.contains("client")) {
                        System.out.println(newnewpart);
                    } else if (newnewpart.contains("pid")) {
                        System.out.println(newnewpart);
                    } else if (newnewpart.contains("2024")) {
                        System.out.println(newnewpart);
                    }   
                }
            }
            System.out.println(); // printing a space to separate each entry
        }     
    }

    public static void dateTime(ArrayList Answer) {
        for (Object data : Answer) {
            String[] parts = ((String) data).split("\\]");
            for (String part : parts) {
                String[] newpart = part.split("\\["); // splitting the lines into parts
                for (String newnewpart : newpart) {
                    if (newnewpart.contains("2024")){ // if the part contains a date, print it
                        System.out.println(newnewpart);
                    }   
                }   
            }
        }
    }    
    public static void IPAddress(ArrayList Answer) {
        ArrayList<String> StoredIPs = new ArrayList<>(Arrays.asList("")); // creating an array of stored IPs
        Boolean check = true;
        for (Object data : Answer) {
            String[] parts = ((String) data).split("\\]");
            for (String part : parts) {
                String[] newpart = part.split("\\["); // splitting up the lines of the entries
                for (String newnewpart : newpart) {
                    if (newnewpart.contains("client") && !newnewpart.contains(":")){ // if the part contains 'client' but not a colon
                        for (Object entry : StoredIPs) { // for each entry in the stored IPs array
                            if (((String) entry).contains(newnewpart)){ // if the new part matches the entry
                                check = false; // the check goes to false
                            }    
                        }
                        if (check) { // if check is true after looking at all the entries
                            StoredIPs.add(newnewpart); // add the new IP to the stored IP array
                        }
                    }    
                }
            } 
        }
        System.out.println(StoredIPs);  // print the stored IPs
    }  

    

    public static ArrayList CheckIPs(ArrayList fileLines, ArrayList IPS) {
        ArrayList<String> relevantFiles = new ArrayList<>(Arrays.asList("")); // creating an empty array
        Boolean check = true;
        for (Object part : fileLines) {
            for (Object data : IPS) {
                String[] ippart = ((String) data).split("\\]");
                for (String ips : ippart) {
                    String[] individualips = ips.split("\\["); // splitting the IPs up
                    for (String finalIP : individualips) {
                        if (!" ".equals(finalIP) && !finalIP.isEmpty() && !((String) part).isEmpty()){ // comparing the IPs to each IP in the log file
                            if (((String) part).contains(finalIP)){ // if the string has the IP in the check = False
                                check = false;      
                             }
                        }   
                    }
                }
            }
            if (check) { // if the check is still true once everything has cycled through
                relevantFiles.add((String) part); // add the IP to the array
            }   
        }
        return relevantFiles; // return the array
    }

    

    public static ArrayList tagReturn(ArrayList fileLines, String Search, String category) {
        ArrayList<String> relevantFiles = new ArrayList<>(Arrays.asList("")); // create an empty array
        for ( Object part : fileLines) { // for each part in the log
            if (((String) part).contains(category) &&((String) part).contains(Search) ){   // if it contains the category and the search term
                
                relevantFiles.add((String) part);// add the part to the array
                
            } 
        }
        return relevantFiles; // return the array
    }
}
