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

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyDoubleWrapper;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

/**
 * This class handles all the SCP operations in the application
 * 
 */
public class SCP
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
    public SCP(String hostname, String username, String password, String portNumber, String pkPath, String passphrase, TextArea textArea_terminalOut,
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
    public boolean keyConnectSCP()
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
            } else
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
    public boolean passwordConnectSCP() throws JSchException
    {
        try
        {
            progress.set(60/100);
            
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            JSch jsch = new JSch();
            jsch.setKnownHosts("C:\\Users\\mauri\\.ssh\\known_hosts");

            progress.set(80/100);
            session = jsch.getSession(username, hostname, portNumber);
            session.setPassword(password);
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
     * This ends the current SCP Session
     */
    public void endSession()
    {
        session.disconnect();
        String terminationOut = textArea_terminalOut.getText().concat(("\n--------------------\nSession terminated."));
        textArea_terminalOut.setText(terminationOut);
        textArea_terminalOut.setScrollTop(Double.MAX_VALUE);
        textArea_terminalOut.appendText("");
        //System.out.println("ByeBye");
    }

    /**
     * This perform SCP transfer from client to server
     * @param local - local file path
     * @param remote - remote file path
     */
    public void scpTo(String local, String remote)
    {

        FileInputStream fis = null;
        try
        {
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("File transfer in progress");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            String lfile = local; //"C:\\Users\\mauri\\Desktop\\test.txt";
            String rfile = remote; //"/home/pi/Desktop/okay.txt";

            boolean ptimestamp = true;

            // exec 'scp -t rfile' remotely
            rfile = rfile.replace("'", "'\"'\"'");
            rfile = "'" + rfile + "'";
            String command = "scp " + (ptimestamp ? "-p" : "") + " -t " + rfile;

            Channel channel = session.openChannel("exec");

            ((ChannelExec) channel).setCommand(command);

            // get I/O streams for remote scp
            OutputStream out = channel.getOutputStream();
            InputStream in = channel.getInputStream();

            channel.connect();

            if (checkAck(in) != 0)
            {
            }

            File _lfile = new File(lfile);

            if (ptimestamp)
            {
                command = "T" + (_lfile.lastModified() / 1000) + " 0";
                // The access time should be sent here,
                // but it is not accessible with JavaAPI ;-<
                command += (" " + (_lfile.lastModified() / 1000) + " 0\n");
                out.write(command.getBytes());
                out.flush();
                if (checkAck(in) != 0)
                {
                }
            }

            // send "C0644 filesize filename", where filename should not include '/'
            long filesize = _lfile.length();
            command = "C0644 " + filesize + " ";
            if (lfile.lastIndexOf('/') > 0)
            {
                command += lfile.substring(lfile.lastIndexOf('/') + 1);
            } else
            {
                command += lfile;
            }
            command += "\n";
            out.write(command.getBytes());
            out.flush();
            if (checkAck(in) != 0)
            {
            }

            // send a content of lfile
            fis = new FileInputStream(lfile);
            byte[] buf = new byte[1024];
            while (true)
            {
                int len = fis.read(buf, 0, buf.length);
                if (len <= 0)
                    break;
                out.write(buf, 0, len); //out.flush();
            }
            fis.close();
            fis = null;
            // send '\0'
            buf[0] = 0;
            out.write(buf, 0, 1);
            out.flush();
            if (checkAck(in) != 0)
            {
            }
            out.close();

            channel.disconnect();
            
            //Alert alert1 = new Alert(Alert.AlertType.INFORMATION);
            //alert1.setTitle("SCP Transfer Complete");
            //alert1.setContentText("The SCP transfer was successfully completed.");
            //alert1.show();
            infDialog_title.setText("SCP Transfer Complete");
            infDialog_txt1.setText("The SCP transfer was successfully completed.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            

        } catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("SCP Transfer Error");
            //alert.setContentText("There was an Error During SCP transfer. Please make sure all details entered are correct before proceeding.");
            //alert.show();
            errDialog_title.setText("SCP Transfer Error");
            errDialog_txt1.setText("There was an Error During SCP transfer. Please make sure");
            errDialog_txt2.setText("all details entered are correct before proceeding.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            

        }

        try
        {
            fis.close();
        } catch (IOException ex)
        {

        }
    }

    /**
     * This perform SCP transfer from server to client
     * @param local - local file path
     * @param remote - remote file path
     */
    public void scpFrom(String local, String remote)
    {
        String lfile = local; //"C:\\Users\\mauri\\Desktop\\test.txt";
        String rfile = remote; //"/home/pi/Desktop/okay.txt";

        FileOutputStream fos = null;
        try
        {
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("Receiving file transfer in progress.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            
            String prefix = null;
            if (new File(lfile).isDirectory())
            {
                prefix = lfile + File.separator;
            }

            // exec 'scp -f rfile' remotely
            rfile = rfile.replace("'", "'\"'\"'");
            rfile = "'" + rfile + "'";
            String command = "scp -f " + rfile;
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);

            // get I/O streams for remote scp
            OutputStream out = channel.getOutputStream();
            InputStream in = channel.getInputStream();

            channel.connect();

            byte[] buf = new byte[1024];

            // send '\0'
            buf[0] = 0;
            out.write(buf, 0, 1);
            out.flush();

            while (true)
            {
                int c = checkAck(in);
                if (c != 'C')
                {
                    break;
                }

                // read '0644 '
                in.read(buf, 0, 5);

                long filesize = 0L;
                while (true)
                {
                    if (in.read(buf, 0, 1) < 0)
                    {
                        // error
                        break;
                    }
                    if (buf[0] == ' ')
                        break;
                    filesize = filesize * 10L + (long) (buf[0] - '0');
                }

                String file = null;
                for (int i = 0;; i++)
                {
                    in.read(buf, i, 1);
                    if (buf[i] == (byte) 0x0a)
                    {
                        file = new String(buf, 0, i);
                        break;
                    }
                }

                //System.out.println("filesize="+filesize+", file="+file);
                // send '\0'
                buf[0] = 0;
                out.write(buf, 0, 1);
                out.flush();

                // read a content of lfile
                fos = new FileOutputStream(prefix == null ? lfile : prefix + file);
                int foo;
                while (true)
                {
                    if (buf.length < filesize)
                        foo = buf.length;
                    else
                        foo = (int) filesize;
                    foo = in.read(buf, 0, foo);
                    if (foo < 0)
                    {
                        // error 
                        break;
                    }
                    fos.write(buf, 0, foo);
                    filesize -= foo;
                    if (filesize == 0L)
                        break;
                }
                fos.close();
                fos = null;

                if (checkAck(in) != 0)
                {
                }

                // send '\0'
                buf[0] = 0;
                out.write(buf, 0, 1);
                out.flush();
            }
            
            channel.disconnect();
            
            //Alert alert1 = new Alert(Alert.AlertType.INFORMATION);
            //alert1.setTitle("SCP Transfer Complete");
            //alert1.setContentText("The SCP transfer was successfully completed.");
            //alert1.show();
            infDialog_title.setText("SCP Transfer Complete");
            infDialog_txt1.setText("The SCP transfer was successfully completed.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            

        } 
        catch (Exception e)
        {

        }
        try
        {
            if (fos != null)
                fos.close();
        } catch (Exception ee)
        {
        }
    }

    /**
     * This checks for successful file transfer
     * @param in - input stream
     * @return
     * @throws IOException 
     */
    static int checkAck(InputStream in) throws IOException
    {
        int b = in.read();
        // b may be 0 for success,
        //          1 for error,
        //          2 for fatal error,
        //          -1
        if (b == 0)
            return b;
        if (b == -1)
            return b;

        if (b == 1 || b == 2)
        {
            StringBuffer sb = new StringBuffer();
            int c;
            do
            {
                c = in.read();
                sb.append((char) c);
            } while (c != '\n');
            if (b == 1)
            { // error
                //System.out.print(sb.toString());
            }
            if (b == 2)
            { // fatal error
                //System.out.print(sb.toString());
            }
        }
        return b;
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
            for (int i = 0; i < connections.size(); ++i)
            {
                myWriter.write(connections.get(i) + ("\n"));
            }
            myWriter.close();

        } catch (Exception e)
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
        } catch (Exception e)
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
