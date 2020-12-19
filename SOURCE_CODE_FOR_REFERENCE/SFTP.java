/**
 *
 * KiteSSH - An SSH, SFTP, SCP and P2P client for Windows
 *
 * UNIVERSITY OF WOLLONGONG - CSIT321 [Project]
 *
 * GROUP: FYP-20-S3-10 - EFFICIENT SSH TUNNELING
 *
 * MEMBERS:
 *
 * Fratini Luca Project Manager lucafratini94@gmail.com
 * Maurice Rizat Kasomwung Backend Programmer mauricerizat@gmail.com
 * Lim Wei Zhi Maximillian Frontend Programmer azure.marine1@gmail.com
 * Chua Man Fu UI/UX Designer manfularry35@gmail.com
 * Pang Chun Weng Software Tester pangchunweng1993@gmail.com
 *
 * SUPERVISOR: Japit Sionggo
 * ASSESSOR: Tian Sion Hui
 *
 * VERSION: 1.0
 * DATE: November 2020
 *
 */
package KiteSSHGUI;

import com.jcraft.jsch.*;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Scanner;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyDoubleWrapper;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;

/**
 * This class handles all the SFTP operations in the application
 * 
 */
public class SFTP extends Thread
{

    String hostname, username, password;
    int portNumber;
    TextArea textArea_terminalOut;
    protected String terminalOut;
    Session session;
    String pwd;
    String pkPath;
    String passphrase;
    
    AnchorPane a_errorDialog;
    TextField errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3;
    AnchorPane a_infoDialog;
    TextField infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3;
    
    ReadOnlyDoubleWrapper progress = new ReadOnlyDoubleWrapper();
    
    /**
     * Constructor 
     * 
     * @param hostname - Server address
     * @param username - Username
     * @param password - Password
     * @param portNumber - Port
     * @param pkPath - Path to private key
     * @param passphrase - Optional passphrase
     * @param textArea_terminalOut - GUI terminal output
     * @param a_errorDialog - For use in alerts
     * @param errDialog_title - For use in alerts
     * @param errDialog_txt1 - For use in alerts
     * @param errDialog_txt2 - For use in alerts
     * @param errDialog_txt3 - For use in alerts
     * @param a_infoDialog - For use in alerts
     * @param infDialog_title - For use in alerts
     * @param infDialog_txt1 - For use in alerts
     * @param infDialog_txt2 - For use in alerts
     * @param infDialog_txt3  - For use in alerts
     */
    public SFTP(String hostname, String username, String password, String portNumber, String pkPath, String passphrase, TextArea textArea_terminalOut,
            AnchorPane a_errorDialog, TextField errDialog_title, TextField errDialog_txt1, TextField errDialog_txt2, TextField errDialog_txt3,
            AnchorPane a_infoDialog, TextField infDialog_title, TextField infDialog_txt1, TextField infDialog_txt2, TextField infDialog_txt3)
    {
        this.hostname = hostname;
        this.username = username;
        this.password = password;
        this.portNumber = Integer.parseInt(portNumber);
        this.textArea_terminalOut = textArea_terminalOut;
        this.terminalOut = "";
        this.pwd = "";
        this.pkPath = pkPath;
        this.passphrase = passphrase;
        
        this.a_infoDialog = a_infoDialog;
        this.infDialog_title = infDialog_title;
        this.infDialog_txt1 = infDialog_txt1;
        this.infDialog_txt2 = infDialog_txt2;
        this.infDialog_txt3 = infDialog_txt3;
        
        this.a_errorDialog = a_errorDialog;
        this.errDialog_title = errDialog_title;
        this.errDialog_txt1 = errDialog_txt1;
        this.errDialog_txt2 = errDialog_txt2;
        this.errDialog_txt3 = errDialog_txt3;
        

    }
    
    /**
     * For progress bar
     * 
     * @return double
     */
    public double getProgress() 
    {
        return progressProperty().get();
    }
    
    /**
     * For progress bar
     * 
     * @return progress
     */
    public ReadOnlyDoubleProperty progressProperty() 
    {
        return progress;
    }
    
    /**
     * This performs key-based authentication with the Server
     * @return true or false
     */
    public boolean keyConnectSFTP()
    {
        try
        {
            progress.set(60/100);
            
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            
            JSch jsch = new JSch();
            jsch.setKnownHosts("C:\\Users\\mauri\\.ssh\\known_hosts");
                
            if (passphrase.equals("") || passphrase == null)
            {
                jsch.addIdentity(pkPath);
            } 
            else
            {
                jsch.addIdentity(pkPath, passphrase);
            }
                        
            progress.set(80/100);
            
            session = jsch.getSession(username, hostname, portNumber);
            session.setConfig(config);
            session.connect();
            //System.out.println("Connected");
            progress.set(100/100);

        } catch (Exception e)
        {
            
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Connection failed");
            //alert.setContentText("Please check your given details and try again.");
            //alert.show();
            errDialog_title.setText("Connection failed");
            errDialog_txt1.setText("Please check your given details and try again.");
            errDialog_txt2.setText("");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
            
            return false;
        }
        
        return true;
    }
    
    /**
     * This performs password based authentication with the Server
     * @return true or false
     * @throws JSchException 
     */
    public boolean passwordConnectSFTP()
    {
        try
        {
            progress.set(60/100);
            
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            JSch jsch = new JSch();
            
            progress.set(80/100);
            
            session = jsch.getSession(username, hostname, portNumber);
            session.setPassword(password);
            session.setConfig(config);
            session.connect();
            
            progress.set(100/100);
        } catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Connection failed");
            //alert.setContentText("Please check your given details and try again.");
            //alert.show();
            errDialog_title.setText("Connection failed");
            errDialog_txt1.setText("Please check your given details and try again.");
            errDialog_txt2.setText("");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
            
            
            return false;
        }
        
        return true;
    }

    /**
     * This ends the current SFTP Session
     */
    public void endSession ()
    {
        session.disconnect();
        String terminationOut = textArea_terminalOut.getText().concat(("\n--------------------\nSession terminated."));
        textArea_terminalOut.setText(terminationOut);
        textArea_terminalOut.setScrollTop(Double.MAX_VALUE);
        textArea_terminalOut.appendText("");
        //System.out.println("ByeBye");
    }
    
    /**
     * This perform SFTP transfer
     * @param type - Transfer type GET/PUT
     * @param local - local file path
     * @param remote - remote file path
     */
    public void SFTPTransfer(String type, String local, String remote) throws JSchException, SftpException
    {
        ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
        channel.connect();

        //System.out.println(type);
        
        try
        {
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("File transfer in progress");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            if (type.equals("GET"))
            {
                channel.get(remote, local);
            } else if (type.equals("PUT"))
            {
                channel.put(local, remote);
            }   
            infDialog_title.setText("SFTP Transfer Complete");
            infDialog_txt1.setText("Your requested SFTP Transfer has been completed.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
        }
        catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("SFTP Transfer errot");
            //alert.setContentText("There was an error during the transfer. Please make sure all details are correct and try again.");
            //alert.show();
            errDialog_title.setText("SFTP Transfer error");
            errDialog_txt1.setText("There was an error during the transfer. Please make sure");
            errDialog_txt2.setText("all details are correct and try again.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
            

        }
        
    }

    /**
     * This sends SFTP commands to be executed in the server shell
     * @param command - Command to execute
     * @return 
     */
    public String SFTPExec(String command)
    {
        if (command.charAt(0) == '\n')
        {
            command = command.substring(1);
        }
        
        //SFTP accepts limited commands
        if (command.indexOf("cd") == -1 && command.indexOf("ls") == -1 && command.indexOf("pwd") == -1 && command.indexOf("terminate") == -1 && command.indexOf("exit") == -1 && command.indexOf("rm") == -1)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Invalid SFTP command");
            //alert.setContentText("This SFTP terminal only accepts directory traversal and file transfer commands.");
            //alert.show();
            errDialog_title.setText("Invalid SFTP command");
            errDialog_txt1.setText("This SFTP terminal only accepts directory traversal and");
            errDialog_txt2.setText("file transfer commands.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
            

            return pwd;
        }
        
        String compositeCommand = "";
        
        boolean getPwd = false;
        
        if (command.indexOf("cd ") != -1)
        {
            compositeCommand = command.concat("; pwd");
            getPwd = true;
        }
        else
        {
            compositeCommand = command;
        }
        
        String oldComposite = compositeCommand;
        
        if (!pwd.equals(""))
        {
            compositeCommand = "cd ".concat(pwd).concat("; ").concat(oldComposite);
        }
        
        try
        {            
            if (command.equals("terminate") || command.equals("exit"))
            {
                endSession();
                return pwd;
            }
            
            File file = new File("tempOut/errorLog.txt");
            FileOutputStream fos = new FileOutputStream(file);
            PrintStream ps = new PrintStream(fos);
            System.setErr(ps);
            
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(compositeCommand);
            channel.setInputStream(null);
            ((ChannelExec) channel).setErrStream(System.err);
            
            InputStream in = channel.getInputStream();
            channel.connect();
            byte[] tmp = new byte[10000000];

            while (true)
            {
                while (in.available() > 0)
                {
                    int i = in.read(tmp, 0, 10000000);
                    if (i < 0)
                        break;

                    terminalOut = textArea_terminalOut.getText();

                    String output = new String(tmp, 0, i);
                    
                    if (getPwd == true)
                    {
                        pwd = output.substring(0, output.length()-1);
                    }
                    
                    terminalOut = terminalOut + "\n" + "\n" + "> " + command + "\n" + output;

//                    System.out.println("pwd: " + pwd);
//                    System.out.println("command: " + command);
//                    System.out.println("compositeCommand: " + compositeCommand);
//                    System.out.println();
                    
                    Platform.runLater(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            textArea_terminalOut.setText(terminalOut);
                            textArea_terminalOut.setScrollTop(Double.MAX_VALUE);
                            textArea_terminalOut.appendText(""); 
                        }
                    });
                }
                if (channel.isClosed())
                {
                    //System.out.println("exit-status: " + channel.getExitStatus());
                    break;
                }
            }
            
            FileReader fileReader = new FileReader(file);   //reads the file  
            BufferedReader br = new BufferedReader(fileReader);  //creates a buffering character input stream  
            
            String line;
            while ((line = br.readLine()) != null)
            { 
                terminalOut = textArea_terminalOut.getText();
                terminalOut = terminalOut + "\n\n" + line;
            }
            
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    textArea_terminalOut.setText(terminalOut);
                    textArea_terminalOut.setScrollTop(Double.MAX_VALUE);
                    textArea_terminalOut.appendText(""); 
                }
            });
            
            fileReader.close();
            
            fos.close();
            
            FileOutputStream fos1 = new FileOutputStream(file);
            fos1.close();
            
            channel.disconnect();

        } catch (Exception e)
        {
            e.printStackTrace();
        }
        return pwd;
    }

    /**
     * This writes the given connection list to the file "savedConnection.txt"
     * @param connections - list of connections to write
     * @throws IOException 
     */
    public void writeToFile(ArrayList<String> connections) throws IOException
    {
        try
        {
            File file = new File("resources/savedConnections.txt");
            FileWriter myWriter = new FileWriter(file);
            for(int i = 0; i < connections.size(); ++i)
            {
                myWriter.write(connections.get(i) + ("\n"));
            }
            myWriter.close();
            
        }
        catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("There was an error");
            //alert.setContentText("Connection details could not be saved.");
            //alert.show();
            errDialog_title.setText("There was an error");
            errDialog_txt1.setText("Connection details could not be saved.");
            errDialog_txt2.setText("");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
            

        }
    }
    
    /**
     * This checks if the current connection is already in the given connection
     * list
     * @param connections - Connection list to check
     * @return 
     */
    public boolean alreadyExists(ArrayList<String> connections)
    {
        try
        {
            for (int i = 0; i < connections.size(); ++i)
            {  
                String data[] = connections.get(i).split(":");

                int data2 = Integer.parseInt(data[2]);

                if (data[0].equals(hostname) && data[1].equals(username) && data2 == portNumber)
                {
                    return true;
                }
            }
        }
        catch (Exception e)
        {
            
        }
        
        return false;
    }
    
    /**
     * This checks if the given connection details match the current connection 
     * details.
     * @param connection
     * @return 
     */
    public boolean match(String connection)
    {
        String data[] = connection.split(":");
            
        int data2 = Integer.parseInt(data[2]);

        if (data[0].equals(hostname) && data[1].equals(username) && data2 == portNumber)
        {
            return true;
        }
        
        return false;
    }
}
