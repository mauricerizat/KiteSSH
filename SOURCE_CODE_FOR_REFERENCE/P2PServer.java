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


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyDoubleWrapper;
import javafx.scene.control.Alert;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class handles all P2P server-side operations
 *
 */
public class P2PServer implements Runnable
{

    private ServerSocket server;
    private String sharedSecret;
    private String initVector;
    private String hostName;
    private String userName;
    private int portNumber;
    private String password;
    protected TextArea terminal;
    private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private final String BASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private boolean stopConnection;
    
    
    
    AnchorPane a_errorDialog;
    TextField errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3;
    AnchorPane a_infoDialog;
    TextField infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3;
    
    /**
     * Constructor
     * 
     * @param ipAddress - Server IP
     * @param portNumber - Port Number
     * @param password - Password
     * @param terminal - GUI Output Terminal 
     * @param a_errorDialog - For use in alerts
     * @param errDialog_title - For use in alerts
     * @param errDialog_txt1 - For use in alerts
     * @param errDialog_txt2 - For use in alerts
     * @param errDialog_txt3 - For use in alerts
     * @param a_infoDialog - For use in alerts
     * @param infDialog_title - For use in alerts
     * @param infDialog_txt1 - For use in alerts
     * @param infDialog_txt2 - For use in alerts
     * @param infDialog_txt3 - For use in alerts
     * @throws Exception 
     */
    public P2PServer(String ipAddress, int portNumber, String password, TextArea terminal,
            AnchorPane a_errorDialog, TextField errDialog_title, TextField errDialog_txt1, TextField errDialog_txt2, TextField errDialog_txt3,
            AnchorPane a_infoDialog, TextField infDialog_title, TextField infDialog_txt1, TextField infDialog_txt2, TextField infDialog_txt3) throws Exception
    {
        this.sharedSecret = "thisisntverygood";
        this.hostName = ipAddress;  
        this.userName = "";
        this.password = password;
        this.portNumber = portNumber;  
        this.terminal = terminal;
        this.stopConnection = false;
        
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
        
        
        if (ipAddress != null && !ipAddress.isEmpty())
            this.server = new ServerSocket(portNumber, 1, InetAddress.getByName(ipAddress));
        else
            this.server = new ServerSocket(portNumber, 1, InetAddress.getLocalHost());
    }
    
    /**
     * This performs P2P Authentication on the Client
     * 
     * @param client - Socket used
     * @param clientAddress - Address of client
     * @return 
     */
    public boolean authenticate(Socket client, String clientAddress) 
    {
        
        try
        {
            //Diffie Hellman Key Exchang
            
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));

            String data = in.readLine(); //The client's public key is received

            String clientPub = getSHA256(data, "thisisntverygood"); //For logging
            
            byte alicePubKeyEnc[] = hexStringToByteArray(data);

            KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

            PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

            DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey) alicePubKey).getParams();

            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamFromAlicePubKey);
            KeyPair bobKpair = bobKpairGen.generateKeyPair();

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKpair.getPrivate());

            byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded(); //The Server's public key is encoded and sent to the Client

            String Server1 = bytesToHex(bobPubKeyEnc);

            PrintWriter out = new PrintWriter(client.getOutputStream(), true);

            out.println(Server1);
            out.flush();
            
            //Generating Shared Secret - Generated Shared secret is a 2048 bit key
            bobKeyAgree.doPhase(alicePubKey, true);
            
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            
            sharedSecret = bytesToHex(bobSharedSecret); //Encoding to hex
            
            data = in.readLine();
                
            String givenMac = data.substring(data.length() - 64);

            String payload = data.substring(0, data.length() - 64); //Standard Encrypton used is AES128

            String mac = getSHA256(payload, sharedSecret.substring(0, 16)); //Hash used is SHA256
            
            
            
            if (mac.equals(givenMac))
            {
                String decrypted = decryptString(payload);
                
                try
                {
                    String creds[] = decrypted.split(" ");
                    if (creds[1].equals(password))
                    {
                        payload = encryptString("200");
                        mac = getSHA256(payload, sharedSecret.substring(0, 16));
                        String toSend = payload + mac;

                        out.println(toSend);
                        out.flush();
                        
                        this.userName = creds[0];
                        
                        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'_Time'HH:mm:ssZZZZ");
                        Date date = new Date();
                        String authTime = dateFormat.format(date);
                        
                        String logCurrent = authTime + " " + this.userName + "@" + client.getRemoteSocketAddress().toString() + ":" + this.portNumber + " " + clientPub;
                        
                        writeToLog(logCurrent);
                    }
                    else
                    {
                        payload = encryptString("401");
                        mac = getSHA256(payload, sharedSecret.substring(0, 16));
                        String toSend = payload + mac;

                        out.println(toSend);
                        out.flush();
                        
                        return false;
                    }
                }
                catch (Exception e)
                {
                        payload = encryptString("401");
                        mac = getSHA256(payload, sharedSecret.substring(0, 16));
                        String toSend = payload + mac;

                        out.println(toSend);
                        out.flush();
                        
                        return false;
                }
            }
            else
            {
                payload = encryptString("401");
                mac = getSHA256(payload, sharedSecret.substring(0, 16));
                String toSend = payload + mac;

                out.println(toSend);
                out.flush();
                
                return false;
            }
            
        }
        catch (Exception e)
        {
            return false;
        }
                
        return true;
    }
    
    /**
     * This is the main server function. It runs on a separate thread from the
     * GUI for practical purposes. 
     * 
     * The server first listens for incoming connection requests, performs 
     * authentication and then listens for incoming shell commands from the
     * authenticate client.
     * 
     */
    @Override
    public void run() 
    {
        try
        {
            String data = null;
            Socket client = this.server.accept(); //Listening for incoming client cnnection requests.
            String clientAddress = client.getInetAddress().getHostAddress();
            
            String terminalOut =  terminal.getText() + "\nIncoming connection from " + clientAddress + "\nAuthenticating...";
            
            displayInTerminal(terminalOut);
            
            if (!authenticate (client, clientAddress))
            {
                terminalOut = terminalOut + "\nConnection refused: Authentication failed.\n";
                displayInTerminal(terminalOut);
                return;
            }

            //Authentication Successful
            
            terminalOut = terminalOut + "\nClient Authenticated. Awaiting input.\n" + "\n" + this.userName + "@" + clientAddress + ":\n";
            displayInTerminal(terminalOut);
            
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));

            while (true)//(data = in.readLine()) != null)
            {
                if (stopConnection == true) //End Connection
                {
                    terminalOut = terminalOut + "\n\nServer Closed";
                    displayInTerminal(terminalOut);
                    break;
                }
                
                data = in.readLine();
                
                String givenMac = data.substring(data.length() - 64);

                String payload = data.substring(0, data.length() - 64);

                String mac = getSHA256(payload, sharedSecret.substring(0, 16));

                //Integrity of received message is always checked before executing
                if (mac.equals(givenMac))
                {
                    //this.initVector = payload.substring(payload.length() - 64);
                    //String cipherString = payload.substring(0, payload.length() - 64);
                    
                    String decryptedMessage = decryptString(payload);

                    if (decryptedMessage.equals("exit") || decryptedMessage.equals("terminate"))
                    {
                        terminalOut = terminalOut + "\n\n------------------------------\nClient has terminated connection.\nRestart the server to listen for new connections.";
                        displayInTerminal(terminalOut);
                        break;
                    }

                    terminalOut = terminalOut + "\nMessage from " + clientAddress + ": " + decryptedMessage;
                    displayInTerminal(terminalOut);

                    String stuff[] = decryptedMessage.split(" ");
                    
                    int cipherType;
                    
                    try
                    {
                        cipherType = Integer.parseInt(stuff[3]);
                        
                        if (cipherType != 1 || cipherType != 2 || cipherType != 3)
                        {
                            cipherType = 2;
                        }
                    } 
                    catch (Exception e)
                    {
                        cipherType = 2;
                    }
                    
                    if (decryptedMessage.contains("put ")) //File Transfer receive from client
                    {
                        
                        
                        receiveFile(client, stuff[2], cipherType);
                        
                        terminalOut = terminal.getText() + "\nWrote " + stuff[2];
                        displayInTerminal(terminalOut);
                        
                        PrintWriter out = new PrintWriter(client.getOutputStream(), true);

                        out.println(encryptString("finite"));
                        
                        
                        out.flush();
                        
                    }
                    else if (decryptedMessage.contains("get ")) //File Transfer send to client
                    {                        
                        sendFile(client, stuff[1], cipherType);
                        
                        terminalOut = terminal.getText() + "\nSent " + stuff[2];
                        displayInTerminal(terminalOut);
                        
                        PrintWriter out = new PrintWriter(client.getOutputStream(), true);

                        String finalData = in.readLine();

                        if (decryptString(finalData).equals("finite"))
                        
                        out.println(encryptString("padding"));
                        out.flush(); 
                    }
                    else
                    {
                        
                        String execOut = execCommand(decryptedMessage);

                        String execOutEnc = encryptString(execOut);

                        PrintWriter out = new PrintWriter(client.getOutputStream(), true);

                        out.println(execOutEnc);
                        out.flush();

                        terminalOut = terminal.getText() + "\n" + execOut;
                        displayInTerminal(terminalOut);
                    }
                } 
                else
                {
                    //Messages that have failed integrity check are displayed but disregarded.
                    terminalOut = terminalOut + "\nCorrupted message from " + clientAddress + " [Disregarded]: " + data;
                    displayInTerminal(terminalOut);
                }
            }
            
            server.close();
            
        }
        catch (Exception e)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("Server run error.");
                    //alert.setContentText("The server ran into an unexpected error during runtime. Please restart the server to try again.");
                    //alert.show();
                    errDialog_title.setText("Server run error.");
                    errDialog_txt1.setText("The server ran into an unexpected error during runtime.");
                    errDialog_txt2.setText("Please restart the server to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }
    }
    
    /**
     * This performs file transfer from Server to Client
     * 
     * @param client - Socket 
     * @param fileName - Name of file to send
     * @param type - Encryption type to use
     */
    public void sendFile(Socket client, String fileName, int type)
    {
        try
        {
            File myFile = new File(fileName);
            if (!myFile.exists())
            {
                Platform.runLater(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        //Alert alert = new Alert(Alert.AlertType.ERROR);
                        //alert.setTitle("Non-existant file.");
                        //alert.setContentText("The file you requested could not be found. Please check the given file-path and try again.");
                        //alert.show();
                        errDialog_title.setText("Non-existant file.");
                        errDialog_txt1.setText("The file you requested could not be found. Please check");
                        errDialog_txt2.setText("the given file-path and try again.");
                        errDialog_txt3.setText("");
                        a_errorDialog.toFront();
                        a_errorDialog.setVisible(true);
                        
                    }
                });
                return;
            }
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("File transfer in progress");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            
            FileInputStream fis = new FileInputStream(myFile);
            BufferedInputStream bis = new BufferedInputStream(fis);

            DataInputStream dis = new DataInputStream(bis);

            PrintWriter out = new PrintWriter(client.getOutputStream(), true);

            //out.println(myFile.getName());

            byte[] buffer = new byte[8192]; //Each packet is 8192 bytes
            int count;

            while ((count = dis.read(buffer)) > 0) //Sending file
            {
                String encrypted = encryptType(bytesToHex(buffer), type);
                
                String mac = getSHA256(encrypted, sharedSecret.substring(0, 16));
                
                String toSend = encrypted + mac;
                
                out.println(toSend);
            }

            String markEnd = encryptType("endFile", type); //End of file flag
            String markEndMac = getSHA256(markEnd, sharedSecret.substring(0, 16));
            String markEndSend = markEnd + markEndMac;
            out.println(markEndSend);

            out.flush();
            infDialog_title.setText("P2P Transfer Complete");
            infDialog_txt1.setText("The P2P transfer was successfully completed.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
        } 
        catch (Exception e)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File transmission error.");
                    //alert.setContentText("There was an error during file transmission. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File transmission error.");
                    errDialog_txt1.setText("There was an error during file transmission. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }
    }
    
    /**
     * This performs file transfer from the Client to Server
     * 
     * @param client - Socket
     * @param fileName - Name of file to transfer
     * @param type - Encryption type used
     */
    public void receiveFile(Socket client, String fileName, int type)
    {
        try
        {
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("Receiving file transfer in progress.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);
            BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));

            //String fileName = in.readLine();

            OutputStream output = new FileOutputStream(fileName);
            
            String data = null;
            while ((data = in.readLine()) != null)
            {
                String receivedMac = data.substring(data.length()-64);
                
                String payload = data.substring(0, data.length()-64);
                
                String mac = getSHA256(payload, sharedSecret.substring(0, 16));
                                
                if (!mac.equals(receivedMac))
                {
                    Platform.runLater(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            //Alert alert = new Alert(Alert.AlertType.ERROR);
                            //alert.setTitle("Integrity of received file could not be verified.");
                            //alert.setContentText("The integrity of the received file could not be verified. This may be caused due to an corruption or data loss in the network during transmission.");
                            //alert.show();
                            errDialog_title.setText("Integrity of received file could not be verified.");
                            errDialog_txt1.setText("The integrity of the received file could not be verified.");
                            errDialog_txt2.setText("This may be caused due to an corruption or data loss in");
                            errDialog_txt3.setText("the network during transmission.");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);
                            
                        }
                    });
                }
                
                String decrypted = decryptType(payload, type);

                if (decrypted.equals("endFile")) //End of file flag
                    break;
                
                byte stuff[] = hexStringToByteArray(decrypted);

                output.write(stuff, 0, stuff.length);
            }

            output.flush();

            output.close();
            //clientData.close();
            infDialog_title.setText("P2P Transfer Complete");
            infDialog_txt1.setText("The P2P transfer was successfully completed.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);

        } catch (Exception e)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File transmission error.");
                    //alert.setContentText("There was an error during file transmission. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File transmission error.");
                    errDialog_txt1.setText("There was an error during file transmission. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });            
        }
    }
    
    /**
     * This terminates the server
     * 
     * @throws IOException 
     */
    public void endServer() throws IOException
    {
        stopConnection = true;
        String terminalOut = terminal.getText();
        terminalOut = terminalOut + "\n\n------------------------\nServer terminated.";
        displayInTerminal(terminalOut);;
    }
    
    /**
     * This displays given output in the terminal
     * 
     * @param terminalOut - Output to display
     */
    public void displayInTerminal(String terminalOut)
    {
        terminal.setText(terminalOut);
        terminal.setScrollTop(Double.MAX_VALUE);
        terminal.appendText(""); 
    }

    /**
     * This sends the received command to windows Powershell to be executed.
     * 
     * Standard output and error messages from the shell are returned.
     * 
     * @param command - Command to execute
     * @return Standard output/error
     */
    public String execCommand(String command)
    {
        String output = "";
        
        command = "powershell.exe  " + command; //Powershell
        try
        {
            Process process = Runtime.getRuntime().exec(command);

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null)
            {
                output = output + line;
                output = output + "\n";
            }

            reader.close();

            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null)
            {
                output = output + line;
                output = output + "\n";
            }

            errorReader.close();

        } catch (IOException e)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("Commnand shell error.");
                    //alert.setContentText("There was an error while attempting to access the command shell. Please try again.");
                    //alert.show();
                    errDialog_title.setText("Commnand shell error.");
                    errDialog_txt1.setText("There was an error while attempting to access the");
                    errDialog_txt2.setText("command shell. Please try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }
        
        return output;
    }

    /**
     * This gives the socket address of the server
     * @return InetAddress
     */
    public InetAddress getSocketAddress()
    {
        return this.server.getInetAddress();
    }

    /**
     * This gives the port of the server
     * @return port - Integer
     */
    public int getPort()
    {
        return this.server.getLocalPort();
    }
    
    /**
     * This encrypts the given string based on the given type
     * 
     * @param value - String to encrypt
     * @param type - Encryption type:
     *                                  1 - Blowfish
     *                                  2 - AES128 (default)
     *                                  3 - AES256
     * 
     * 
     * @return encrypted String
     */
    public String encryptType(String value, int type)
    {
        try
        {
            this.initVector = generateIV();
            
            byte encrypted[];
            
            if (type == 3) //AES256
            {
                String key = sharedSecret.substring(0, 32);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

                encrypted = cipher.doFinal(value.getBytes());
            }
            else if (type == 1) //Blowfish
            {
                String key = sharedSecret.substring(0, 56);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 8).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "Blowfish");

                Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

                encrypted = cipher.doFinal(value.getBytes());
            }
            else //AES128
            {
                String key = sharedSecret.substring(0, 16);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

                encrypted = cipher.doFinal(value.getBytes());
            }
            
            String ciphertext = Base64.getEncoder().encodeToString(encrypted);

            String payload = ciphertext + this.initVector;
            
            return payload;
            
        } 
        catch (Exception ex)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File encryption error.");
                    //alert.setContentText("There was an error during file encryption. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File encryption error.");
                    errDialog_txt1.setText("There was an error during file encryption. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }
        return null;
    }
    
    /**
     * This decrypts the given string based on the given type
     * 
     * @param encrypted - String to decrypt
     * @param type - Decryption type:
     *                                  1 - Blowfish
     *                                  2 - AES128 (default)
     *                                  3 - AES256
     * 
     * 
     * @return decrypted String
     */
    public String decryptType(String encrypted, int type)
    {
        try
        {
            this.initVector = encrypted.substring(encrypted.length()-64);
            String ciphertext = encrypted.substring(0, encrypted.length()-64);
            
            if (type == 3) //AES256
            {
                String key = sharedSecret.substring(0, 32);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

                return new String(original);
            }
            else if (type == 1) //Blowfish
            {
                String key = sharedSecret.substring(0, 56);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 8).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "Blowfish");

                Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

                return new String(original);
            }
            else //AES128
            {
                String key = sharedSecret.substring(0, 16);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

                return new String(original);
            }
        } 
        catch (Exception ex)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File decryption error.");
                    //alert.setContentText("There was an error during file decryption. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File decryption error.");
                    errDialog_txt1.setText("There was an error during file decryption. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }

        return null;
    }

    /**
     * This encrypts the String with AES128
     * 
     * @param value - String to encrypt
     * @return Encrypted String
     */
    public String encryptString(String value)
    {
        try
        {
            this.initVector = generateIV();
            
            String key = sharedSecret.substring(0, 16);
            
            IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            
            String ciphertext = Base64.getEncoder().encodeToString(encrypted);

            String payload = ciphertext + this.initVector;
            
            return payload;
            
        } catch (Exception ex)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File encryption error.");
                    //alert.setContentText("There was an error during file encryption. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File encryption error.");
                    errDialog_txt1.setText("There was an error during file encryption. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }
        return null;
    }
    
    /**
     * This decrypts the String with AES128
     * 
     * @param value - String to derypt
     * @return Decrypted String
     */
    public String decryptString(String encrypted)
    {
        try
        {
            this.initVector = encrypted.substring(encrypted.length()-64);
            String ciphertext = encrypted.substring(0, encrypted.length()-64);
            
            String key = sharedSecret.substring(0, 16);
            
            IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

            return new String(original);
        } catch (Exception ex)
        {
            Platform.runLater(new Runnable()
            {
                @Override
                public void run()
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("File decryption error.");
                    //alert.setContentText("There was an error during file decryption. You may need to restart the connection to try again.");
                    //alert.show();
                    errDialog_title.setText("File decryption error.");
                    errDialog_txt1.setText("There was an error during file decryption. You may need");
                    errDialog_txt2.setText("to restart the connection to try again.");
                    errDialog_txt3.setText("");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);
                    
                }
            });
        }

        return null;
    }

    /**
     * This generates a 512 bit Initialization Vector
     * @return 512 bit IV
     */
    public String generateIV()
    {
        String IV = "";

        Random rand = new Random();

        for (int i = 0; i < 64; ++i)
        {
            IV = IV + BASE.charAt(rand.nextInt(BASE.length()));
        }

        return IV;
    }
    
    /**
     * This returns a SHA256 keyed hash of the given String
     * 
     * @param data - String to hash
     * @param key - Key
     * 
     * @return - Hash
     * 
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException 
     */
    public String getSHA256(String data, String key) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(signingKey);
        return bytesToHex(mac.doFinal(data.getBytes()));
    }

    /**
     * This converts a byte array to its equivalent hexadecimal string
     * 
     * @param bytes - Byte array
     * @return Equivalent hexadecimal string
     */
    public String bytesToHex(byte[] bytes)
    {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++)
        {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * This converts a hexadecimal string to its equivalent byte array
     * 
     * @param s - hexadecimal string
     * @return Equivalent Byte array
     */
    public byte[] hexStringToByteArray(String s)
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * This writes the current client connection info to the log file "log.txt"
     * @param info - Client info to log
     */
    public void writeToLog(String info)
    {
        try
        {
            File file = new File("resources/log.txt");
            FileWriter myWriter = new FileWriter(file, true);
            myWriter.write(info + ("\n"));
            myWriter.close();
        }
        catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Log Error");
            //alert.setContentText("The new connection could not be logged. Please ensure the integrity of the log file.");
            //alert.show();
            errDialog_title.setText("Log Error");
            errDialog_txt1.setText("The new connection could not be logged. Please ensure");
            errDialog_txt2.setText("the integrity of the log file.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);
            
        }
    }

}

