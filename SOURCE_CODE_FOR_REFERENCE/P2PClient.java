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
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Formatter;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyDoubleWrapper;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class handles all P2P client-side operations
 *
 */
public class P2PClient
{

    private Socket socket;
    private String hostname;
    private String username;
    private int portNumber;
    private Scanner scanner;
    private String sharedSecret;
    private String initVector;
    private String password;
    protected TextArea terminal;
    private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); //To use for encoding
    private final String BASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"; //To use for encoding

    AnchorPane a_errorDialog;
    TextField errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3;
    AnchorPane a_infoDialog;
    TextField infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3;
    ReadOnlyDoubleWrapper progress = new ReadOnlyDoubleWrapper();

    /**
     * Constructor
     *
     * @param serverAddress - Address of the server
     * @param serverPort - Server port number
     * @param username - Username
     * @param password - Password
     * @param terminal - GUI terminal for output
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
     *
     * @throws Exception
     */
    public P2PClient(InetAddress serverAddress, int serverPort, String username, String password, TextArea terminal,
            AnchorPane a_errorDialog, TextField errDialog_title, TextField errDialog_txt1, TextField errDialog_txt2, TextField errDialog_txt3,
            AnchorPane a_infoDialog, TextField infDialog_title, TextField infDialog_txt1, TextField infDialog_txt2, TextField infDialog_txt3) throws Exception
    {
        this.hostname = serverAddress.toString();
        this.portNumber = serverPort;
        this.username = username;
        this.socket = new Socket(serverAddress, serverPort);
        this.scanner = new Scanner(System.in);
        this.sharedSecret = "thisisntverygood";
        this.password = password;
        this.terminal = terminal;

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
     * @return
     */
    public double getProgress()
    {
        return progressProperty().get();
    }

    /**
     * For progress bar
     * @return progress
     */
    public ReadOnlyDoubleProperty progressProperty()
    {
        return progress;
    }

    /**
     * This allows the P2P connection socket to be closed from another class
     * 
     * @throws IOException 
     */
    public void closeSocket() throws IOException
    {
        this.socket.close();
    }

    /**
     * This performs P2P Authentication with the Server
     * 
     * @return true or false
     */
    public boolean authenticate()
    {
        try
        {
            this.socket.setSoTimeout(30000);

            progress.set(40 / 100);
            PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);

            //Diffie Hellman Key Exchange
            
            KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
            aliceKpairGen.initialize(2048);
            KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
            aliceKeyAgree.init(aliceKpair.getPrivate());

            byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded(); //The client's public key is encoded and sent to the Server

            String Client1 = bytesToHex(alicePubKeyEnc);

            out.println(Client1);
            out.flush();

            progress.set(60 / 100);

            BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

            String data = in.readLine();

            byte bobPubKeyEnc[] = hexStringToByteArray(data); //The Server's public key is received

            //Generating Shared Secret - Generated Shared secret is a 2048 bit key
            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
            PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
            aliceKeyAgree.doPhase(bobPubKey, true);
            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            int aliceLen = aliceSharedSecret.length;

            System.out.println(aliceSharedSecret.length);
            sharedSecret = bytesToHex(aliceSharedSecret); //Encoding to hex

            progress.set(70 / 100);

            //Authenticating password
            String creds = this.username + " " + this.password;

            String payload = encryptString(creds); //Standard Encrypton used is AES128
            String mac = getSHA256(payload, sharedSecret.substring(0, 16)); //Hash used is SHA256
            String toSend = payload + mac;

            out.println(toSend);
            out.flush();

            data = in.readLine();

            String givenMac = data.substring(data.length() - 64);

            payload = data.substring(0, data.length() - 64);

            mac = getSHA256(payload, sharedSecret.substring(0, 16));

            progress.set(80 / 100);

            if (mac.equals(givenMac))
            {
                String decrypted = decryptString(payload);

                if (!decrypted.equals("200"))
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("Client authentication failed.");
                    //alert.setContentText("Your client machine could not be authenticated with the server. Please check your provided credentials and try again and try again.");
                    //alert.show();
                    errDialog_title.setText("Client authentication failed.");
                    errDialog_txt1.setText("Your client machine could not be authenticated with the");
                    errDialog_txt2.setText("server. Please check your provided credentials and");
                    errDialog_txt3.setText("try again.");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);

                    return false;
                }
            } else
            {
                return false;
            }

        } catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Client authentication error.");
            //alert.setContentText("There was an error during quthentication with the server. Please restart the connection and try again.");
            //alert.show();
            errDialog_title.setText("Client authentication error.");
            errDialog_txt1.setText("There was an error during quthentication with the server.");
            errDialog_txt2.setText("Please restart the connection and try again.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

            return false;
        }

        return true;
    }
    
    /**
     * This sends a command to the P2P Server
     * 
     * @param input - String containing the command to execute at the P2P Server
     */
    public void sendCommand(String input)
    {
        try
        {
            String payload = encryptString(input);

            String mac = getSHA256(payload, sharedSecret.substring(0, 16));

            PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);

            String toSend = payload + mac;

            out.println(toSend);
            out.flush();

            String terminalOut = terminal.getText();

            String stuff[] = input.split(" ");

            int cipherType; //Encryption type

            try
            {
                cipherType = Integer.parseInt(stuff[3]);

                if (cipherType != 1 || cipherType != 2 || cipherType != 3)
                {
                    cipherType = 2;
                }
            } catch (Exception e)
            {
                cipherType = 2;
            }

            if (input.contains("put ")) //File Transfer - Put
            {
                if (stuff.length < 3)
                {
                    terminalOut = terminalOut + "\nInvalid put command format.";
                    displayInTerminal(terminalOut);
                } else
                {
                    sendFile(stuff[1], cipherType);
                }
            } else if (input.contains("get ")) //File Transfer - Get
            {
                if (stuff.length < 3)
                {
                    terminalOut = terminalOut + "\nInvalid put command format.";
                    displayInTerminal(terminalOut);
                } else
                {
                    receiveFile(stuff[2], cipherType);

                    terminalOut = terminal.getText() + "\nWrote " + stuff[2];
                    displayInTerminal(terminalOut);

                    out.println(encryptString("finite"));
                    out.flush();
                }
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

            String data = in.readLine();

            String displayOut = decryptString(data);

            if (displayOut.equals("finite"))
            {
                terminalOut = terminal.getText() + "\n" + "Sent file " + stuff[1];
                displayInTerminal(terminalOut);
                return;
            } 
            else if (!displayOut.equals("padding"))
            {
                terminalOut = terminalOut + "\n" + displayOut;

                displayInTerminal(terminalOut);

                if (input.equals("exit") || input.equals("terminate"))
                    return;
            }

            //out.close();
        } catch (Exception e)
        {
            //Alert alert = new Alert(Alert.AlertType.ERROR);
            //alert.setTitle("Commnand shell error.");
            //alert.setContentText("There was an error while attempting to access the remote shell. Please try again.");
            //alert.show();
            errDialog_title.setText("Commnand shell error.");
            errDialog_txt1.setText("There was an error while attempting to access the remote");
            errDialog_txt2.setText("shell. Please try again.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

        }
    }

    /**
     * This performs file transfer from Client to Server
     * 
     * @param fileName - Name of file to send
     * @param type - Encryption type to use
     */
    public void sendFile(String fileName, int type)
    {
        try
        {
            File myFile = new File(fileName);
            if (!myFile.exists())
            {
                //Alert alert = new Alert(Alert.AlertType.ERROR);
                //alert.setTitle("Non-existant file.");
                //alert.setContentText("The file you requested could not be found. Please check the file-path and try again.");
                //alert.show();
                errDialog_title.setText("Non-existant file.");
                errDialog_txt1.setText("The file you requested could not be found. Please check");
                errDialog_txt2.setText("the file-path and try again.");
                errDialog_txt3.setText("");
                a_errorDialog.toFront();
                a_errorDialog.setVisible(true);

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

            PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);

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

        } catch (Exception e)
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
    }

    /**
     * This performs file transfer from the Server to Client
     * 
     * @param fileName - Name of file to transfer
     * @param type - Encryption type used
     * 
     */
    public void receiveFile(String fileName, int type)
    {
        try
        {
            infDialog_title.setText("Transferring");
            infDialog_txt1.setText("Receiving file transfer in progress.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);

            BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

            //String fileName = in.readLine();
            OutputStream output = new FileOutputStream(fileName);

            String data = null;
            while ((data = in.readLine()) != null)
            {
                String receivedMac = data.substring(data.length() - 64);

                String payload = data.substring(0, data.length() - 64);

                String mac = getSHA256(payload, sharedSecret.substring(0, 16));

                if (!mac.equals(receivedMac))
                {
                    //Alert alert = new Alert(Alert.AlertType.ERROR);
                    //alert.setTitle("Integrity of received file could not be verified.");
                    //alert.setContentText("The integrity of the received file could not be verified. This may be caused due to an corruption or data loss in the network during transmission.");
                    //alert.show();
                    errDialog_title.setText("Integrity of received file could not be verified.");
                    errDialog_txt1.setText("The integrity of the received file could not be verified. This");
                    errDialog_txt2.setText("may be caused due to an corruption or data loss in the");
                    errDialog_txt3.setText("network during transmission.");
                    a_errorDialog.toFront();
                    a_errorDialog.setVisible(true);

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
            this.initVector = encrypted.substring(encrypted.length() - 64);
            String ciphertext = encrypted.substring(0, encrypted.length() - 64);

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
            else //AES256
            {
                String key = sharedSecret.substring(0, 16);

                IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

                return new String(original);
            }
        } catch (Exception ex)
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
            this.initVector = encrypted.substring(encrypted.length() - 64);
            String ciphertext = encrypted.substring(0, encrypted.length() - 64);

            String key = sharedSecret.substring(0, 16);

            IvParameterSpec iv = new IvParameterSpec(initVector.substring(0, 16).getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));

            return new String(original);
        } catch (Exception ex)
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
     * This writes all the connections in the given list to the file
     * "savedConnections.txt"
     * 
     * @param connections - List of connections to write
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
     * This checks if the given connection list contains the current connection
     * details
     * 
     * @param connections - List to check
     * @return true or false
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
     * details
     * 
     * @param connection - List to check
     * @return true or false
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
