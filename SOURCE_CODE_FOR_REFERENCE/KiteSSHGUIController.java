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
import com.jcraft.jsch.SftpException;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;
import com.jcraft.jsch.KeyPair;
import java.io.BufferedReader;
import java.io.File;
import java.io.PrintStream;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.RadioButton;
//import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.shape.Rectangle;
import javafx.stage.FileChooser;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Optional;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.application.Platform;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.scene.Node;
import javafx.scene.control.ProgressBar;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.TextFlow;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

/**
 * This class is the primary controller of the KiteSSH Application
 *
 * All GUI events are handled here and directed to their appropriate functions
 */
public class KiteSSHGUIController implements Initializable
{

    protected FileChooser chooseFile = new FileChooser(); //File chooser

    @FXML
    private ImageView folderImg; //Image View for logo

    //Text Fields
    @FXML
    protected TextField pageDescription, currentDirectory, p2pServerIP, p2pServerPort, p2pServerPassword,
            add_hName, add_port, add_privateKey, add_privateKeyText, add_passphraseText, add_pwText, add_uName,
            localDirectory, localFilename, remoteDirectory, remoteFilename, keySaveDirectory, keyFileName, scpLocalFilePath,
            scpLocalFileName, scpRemoteFilePath, serverRun_address, serverRun_port, errDialog_title, errDialog_txt1,
            errDialog_txt2, errDialog_txt3, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3, cfmDialog_title,
            cfmDialog_txt1, cfmDialog_txt2, cfmDialog_txt3;

    //Text Areas
    @FXML
    protected TextArea textArea_terminal, textArea_terminalOut, textArea_SSHKey;

    //Password Fields
    @FXML
    private PasswordField add_pw, add_passphrase, keyPassphrase;

    //Combo Boxes
    @FXML
    private ComboBox add_cType, c_sftpTransferType, scpTransferType, historyCombo;

    //Check Boxes
    @FXML
    private CheckBox checkbx_SaveConn, check_executeWithEnter;

    //Buttons
    @FXML
    private Button addBtn, deleteBtn, editBtn, button_clearTerminal, button_endConnection, serverStartBtn, GenAndSaveBtn,
            connectBtn, cancelBtn, saveChangesBtn, button_endServer, button_restartServer, okBtn, sftpTransferButton, minimizeBtn,
            resizeAppBtn, button_execute;

    //Flow Pane
    @FXML
    private FlowPane topMenu;

    //Text Flow
    @FXML
    private TextFlow actionBar;

    //Grid Pane
    @FXML
    private GridPane logoGrid;

    //Vertical Box
    @FXML
    private VBox connectionList;

    //Radio Buttons
    @FXML
    private RadioButton add_radio_pw, add_radio_privKey;

    //Rectangle to cover password textfield or privatekey textfield
    @FXML
    Rectangle add_coverPW, add_coverPrivKey;

    //Anchor Panes
    @FXML
    private AnchorPane a_home, a_add, a_terminal, a_delete, a_edit, a_transfer, passwordBox, keyBox, a_SSHKeyGen, a_scpControl,
            baseAnchorPane, a_createp2pServer, a_connectionLoading, a_errorDialog, a_infoDialog, a_confirmDialog;

    //Progress Bar
    @FXML
    private ProgressBar pBar_load;

    //Class elements
    SSH ssh1; //SSH Instance
    SFTP sftp1; //SFTP Instance
    SCP scp1; //SCP Instance
    P2PClient p2pClient; //P2P Client Instance
    P2PServer p2pServer; //P2P Server Instance

    String sftpDirectory = ""; //SFTP file directory
    boolean sessionLive = false; //Flag for live session
    String sftpTerminalCommand = ""; //Command for SFTP 

    ArrayList<String> connections = new ArrayList<String>(); //Stores list of saved connections read from file savedConnections.txt
    ArrayList<Button> buttonList; //List of buttons for selecting saved connections
    Button currentButton = new Button(); //Stores reference to clicked connection button
    String changedConnection = ""; //Stores information on connection in case of edit

    //For use in custom alerts
    boolean yesNoBtnCheck = false;
    boolean toCloseWindowCheck = false;
    StringBuffer sb = new StringBuffer("");

    /**
     * Performs SSH Key Generation
     *
     * A 1024 bit RSA key pair is generated with optional encryption based on
     * user-given passphrase The generated Key-Pair is saved to user-selected
     * directory
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void doKeyGen(ActionEvent event)
    {
        try
        {
            if (keySaveDirectory.getText().equals(""))
            {
                //Alert alert = new Alert(AlertType.ERROR);
                //alert.setTitle("SSH Key Save location not selected");
                //alert.setContentText("Please select a location to save you SSH Key-Pair at befor proceeding.");
                //alert.show();
                errDialog_title.setText("SSH Key Save location not selected");
                errDialog_txt1.setText("Please select a location to save your SSH Key-Pair at before");
                errDialog_txt2.setText("proceeding.");
                errDialog_txt3.setText("");
                a_errorDialog.toFront();
                a_errorDialog.setVisible(true);

            } else
            {
                String fullSaveDirectory = keySaveDirectory.getText() + "\\" + keyFileName.getText();

                JSch jsch = new JSch();

                KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.RSA);

                if (keyPassphrase.getText().equals("") || keyPassphrase.getText() == null) //No passphrase
                {
                    kpair.writePrivateKey(fullSaveDirectory);
                    kpair.writePublicKey(fullSaveDirectory + ".pub", "");
                } else //Passphrase given
                {
                    String passphrase = keyPassphrase.getText();
                    //byte passphrase[] = keyPassphrase.getText().getBytes();
                    kpair.setPassphrase(passphrase);
                    kpair.writePrivateKey(fullSaveDirectory);
                    kpair.writePublicKey(fullSaveDirectory + ".pub", "");
                }
                String fPrint = "Finger print: " + kpair.getFingerPrint();

                kpair.dispose();

                add_privateKey.setText(fullSaveDirectory);
                add_passphrase.setText(keyPassphrase.getText());

                //Alert alert = new Alert(AlertType.INFORMATION);
                //alert.setTitle("SSH Transfer Complete");
                //alert.setContentText("Your SSH Key-Pair has been generated and saved.\n" + fPrint);
                //alert.show();
                infDialog_title.setText("Key Generation complete");
                infDialog_txt1.setText("Your SSH Key-Pair has been generated and saved.");
                infDialog_txt2.setText("" + fPrint);
                infDialog_txt3.setText("");
                a_infoDialog.toFront();
                a_infoDialog.setVisible(true);

                cancelKeygen(event);
            }
        } catch (Exception e)
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("SSH Keygen Error");
            //alert.setContentText("There was an error during SSH key generation. Please try again.");
            //alert.show();
            errDialog_title.setText("SSH Keygen Error");
            errDialog_txt1.setText("There was an error during SSH key generation.");
            errDialog_txt2.setText("Please try again.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

        }
    }

    /**
     * This displays the KeyGen Window
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void keyGenWindow(ActionEvent event)
    {
        a_add.setDisable(true);

        a_terminal.setDisable(true);
        a_SSHKeyGen.setVisible(true);
        a_SSHKeyGen.toFront();
        topMenu.setDisable(true);
        actionBar.setDisable(true);
        logoGrid.setDisable(true);
        connectionList.setDisable(true);
    }

    /**
     * This cancels KeyGen and hides the KeyGen window
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void cancelKeygen(ActionEvent event)
    {
        a_add.setDisable(false);

        a_terminal.setDisable(false);
        a_SSHKeyGen.setVisible(false);
        topMenu.setDisable(false);
        actionBar.setDisable(false);
        logoGrid.setDisable(false);
        connectionList.setDisable(false);
    }

    /**
     * This displays a directory chooser to display the directory where
     * the generated key is to be saved
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void chooseKeySaveDirectory(ActionEvent event)
    {
        try
        {
            DirectoryChooser chooser = new DirectoryChooser();

            chooser.setTitle("JavaFX Projects");
            chooser.setInitialDirectory(new File("C:/Users/"));
            File selectedDirectory = chooser.showDialog(KiteSSH.stage);

            //System.out.println(selectedDirectory.getAbsolutePath());
            keySaveDirectory.setText(selectedDirectory.getAbsolutePath());
        } catch (Exception e)
        {

        }
    }

    /**
     * This brings the GUI home. 
     * In case of a connection being added, a suer confirmation is required
     * to return home.
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void returnHome(ActionEvent event)
    {

        if (toCloseWindowCheck == false)
        {
            cfmDialog_title.setText("Cancel Adding Connection");
            cfmDialog_txt1.setText("Your connection will not be saved, click Yes to cancel.");
            cfmDialog_txt2.setText("Click No to continue adding connection details.");
            cfmDialog_txt3.setText("");
            sb.replace(0, sb.length(), "returnHome");
            a_confirmDialog.toFront();
            a_confirmDialog.setVisible(true);

        }
        if (toCloseWindowCheck == true)
        {
            toCloseWindowCheck = false;
            pageDescription.setText("Home");
            a_confirmDialog.setVisible(false);

            a_home.setVisible(true);
            a_add.setVisible(false);

            addBtn.setDisable(false);
            deleteBtn.setDisable(true);
            editBtn.setDisable(true);
        }
        if (a_createp2pServer.isVisible() == true)
        {
            a_createp2pServer.setVisible(false);
            pageDescription.setText("Home");
            a_home.setVisible(true);
            addBtn.setDisable(false);
            deleteBtn.setDisable(true);
            editBtn.setDisable(true);
        }
    }

    /**
     * This enters a selected command from the history combo-box (hostoryCombo)
     * into the terminal.
     * In case "--" is selected, no command will be added to the terminal.
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void detectHistory(ActionEvent event)
    {
        if (!historyCombo.getValue().equals("--"))
        {
            textArea_terminal.setText((String) historyCombo.getValue());
        }
    }

    /**
     * This sends commands in the terminal to the relevant connected SSH, SFTP 
     * or P2P shell. 
     * Special commands "exit", "terminate" and "help_local" in case of P2P are
     * handled here.
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void executeCommand(ActionEvent event)
    {
        try
        {
            if (sessionLive == false) //If no session is running.
            {
                return;
            }

            String command = textArea_terminal.getText(); //The user supplied command
            textArea_terminal.setText("");

            if (command.charAt(0) == '\n') //Filtering out nextLine escape character
            {
                command = command.substring(1);
            }
            
            //In case of "exit" or "terminate" commands
            if (command.contains("terminate") || command.contains("exit"))
            {
                String testTerminate = command.replaceAll("[\\n\\t ]", "");

                if (testTerminate.equals("terminate") || testTerminate.equals("exit"))
                {
                    terminateConnection(event);
                    return;
                }
            }

            historyCombo.getItems().addAll(command); //Appending command to history

            if (add_cType.getValue() == "SSH") //SSH
            {
                ssh1.SSHExec(command); //SSH shell execution
            } 
            else if (add_cType.getValue() == "SFTP") //SFTP
            {
                if (command.contains("get ") || command.contains("put ")) //SFTP Transfer
                {
                    sftpTerminalCommand = command;
                    sftpTransfer(event);
                } else
                {
                    sftpDirectory = sftp1.SFTPExec(command); //SFTP shell execution
                }
            }
            if (add_cType.getValue() == "P2P") //P2P
            {
                String terminalOut = textArea_terminalOut.getText() + "\n" + command;
                textArea_terminalOut.setText(terminalOut);

                if (command.contains("help_local")) //Display help - This command is handled locally
                {
                    String instructions = "\nHELP:\nEnter \"terminate\" or \"exit\" to end the connection.\n"
                            + "\nFor file transfers use the key words \"put\" or \"get\" followed by the\nlocal directory and the remote directory"
                            + "\n\nEg: For uploads: get localFile.exe remoteFile.exe"
                            + "\n     For downloads: put localFile.exe remoteFile.exe"
                            + "\n\nAppend the options 1, 2 or 3 to select from the encryption methods\nto use for file transfer."
                            + "\n\nThe available encryption methods and their respective selector\noptions are:"
                            + "\n\tBlowfish (fastest - less secure) [Option 1]"
                            + "\n\tAES128 (moderately fast - more secure) [Option 2]"
                            + "\n\tAES256 (significantly slower - most secure) [Option 3]"
                            + "\n\nAES128 is set as the default encryption method."
                            + "\n\nEg: For uploads: get localFile.exe remoteFile.exe 2"
                            + "\n     For downloads: put localFile.exe remoteFile.exe 1";

                    terminalOut = textArea_terminalOut.getText() + "\n" + instructions;
                    textArea_terminalOut.setText(terminalOut);
                    textArea_terminalOut.setScrollTop(Double.MAX_VALUE);
                } 
                else
                {
                    p2pClient.sendCommand(command); //P2P Server shell execution
                }
            }
        } catch (Exception e)
        {
            //None
        }
    }

    /**
     * This detects the key-press of the ENTER key when the user is typing in
     * the command terminal. 
     * 
     * If the Check Box check_executeWithEnter is selected this function calls
     * executeCommand()
     * 
     * @param ke - JavaFx Key event
     * 
     */
    @FXML
    public void detectEnter(KeyEvent ke) throws FileNotFoundException, IOException
    {
        try
        {
            if (ke.getCode().equals(KeyCode.ENTER) && check_executeWithEnter.isSelected())
            {
                ActionEvent event = new ActionEvent();
                executeCommand(event);
            }
        } catch (Exception e)
        {

        }
    }

    /**
     * This terminates the current SSH, SCP, SFTP or P2P connection
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void terminateConnection(ActionEvent event) throws FileNotFoundException, IOException
    {
        if (sessionLive == true)
        {
            //Alert alert = new Alert(AlertType.CONFIRMATION);
            //alert.setTitle("Warning");
            //alert.setHeaderText("You are about to terminate a connection. Unsaved data may be lost. Are you sure you want to proceed?");
            //alert.setContentText("Terminate Connection");
            //Optional<ButtonType> option = alert.showAndWait();
            //if (option.get() == null)            {            } 
            //else if (option.get() == ButtonType.OK)
            if (toCloseWindowCheck == false) //Confirmation
            {
                yesNoBtnCheck = false;
                cfmDialog_title.setText("Warning");
                cfmDialog_txt1.setText("You are about to terminate a connection. Unsaved data");
                cfmDialog_txt2.setText("may be lost. Are you sure you want to proceed?");
                cfmDialog_txt3.setText("");

                sb.replace(0, sb.length(), "terminateConnection");
                a_confirmDialog.toFront();
                a_confirmDialog.setVisible(true);

            }
            if (toCloseWindowCheck == true)
            {
                toCloseWindowCheck = false;
                a_confirmDialog.setVisible(false);

                addBtn.setDisable(false);
                if (yesNoBtnCheck == true)
                {
                    if (add_cType.getValue() == "SSH") //SSH
                    {
                        ssh1.SSHExec("terminate");
                    } 
                    else if (add_cType.getValue() == "SFTP") //SFTP
                    {
                        sftpDirectory = sftp1.SFTPExec("terminate");
                    } 
                    else if (add_cType.getValue() == "SCP") //SCP
                    {
                        scp1.endSession();
                        a_scpControl.setVisible(false);
                        a_add.setVisible(true);
                    } 
                    else if (add_cType.getValue() == "P2P") //P2P
                    {
                        p2pClient.closeSocket();
                    }

                    sessionLive = false;
                    initializeConnectionList(0); 
                } //else if (option.get() == ButtonType.CANCEL)
                else if (yesNoBtnCheck == false)
                {

                }
            }
        }
    }

    /**
     * This clears the output terminal
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    public void terminalClear(ActionEvent event)
    {
        String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
        textArea_terminalOut.setText(terminalOut);
    }

    /**
     * This calls the file/directory selection window for use in SFTP transfer
     * 
     * @param event - JavaFx event
     * 
     */
    @FXML
    void chooseLocalSFTPDirectory(ActionEvent event)
    {
        try
        {
            if (c_sftpTransferType.getValue().equals("GET")) //Directory Choice
            {
                DirectoryChooser chooser = new DirectoryChooser();

                chooser.setTitle("JavaFX Projects");
                chooser.setInitialDirectory(new File("C:/Users/"));
                File selectedDirectory = chooser.showDialog(KiteSSH.stage);

                //System.out.println(selectedDirectory.getAbsolutePath());
                localDirectory.setText(selectedDirectory.getAbsolutePath());
            } 
            else //File Choice
            {
                File file = chooseFile.showOpenDialog(folderImg.getScene().getWindow());
                localDirectory.setText(file.getParent());
                localFilename.setText(file.getName());
            }
        } catch (Exception e)
        {

        }
    }

    /**
     * This starts the SFTP transfer
     * 
     * @param event - JavaFx event
     * @exception JSchException, SftpException
     */
    @FXML
    void startSFTPTransfer(ActionEvent event) throws JSchException, SftpException
    {
        if (localDirectory.getText().equals("") || localFilename.getText().equals("") || remoteDirectory.getText().equals("") || remoteFilename.getText().equals(""))
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("Required Fields Empty");
            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
            //alert.show();
            errDialog_title.setText("Required Fields Empty");
            errDialog_txt1.setText("Please make sure all required fields are filled");
            errDialog_txt2.setText("before proceeding.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

            return;
        }

        String localPath = localDirectory.getText() + "\\" + localFilename.getText();
        String remotePath = remoteDirectory.getText() + remoteFilename.getText();

        //Handle errors with slashes and such
        sftp1.SFTPTransfer((String) c_sftpTransferType.getValue(), localPath, remotePath);
        
        //Alert alert = new Alert(AlertType.INFORMATION);
        //alert.setTitle("SFTP Transfer Complete");
        //alert.setContentText("Your requested SFTP Transfer has been completed.");
        //alert.show();
//        infDialog_title.setText("SFTP Transfer Complete");
//        infDialog_txt1.setText("Your requested SFTP Transfer has been completed.");
//        infDialog_txt2.setText("");
//        infDialog_txt3.setText("");
//        a_infoDialog.toFront();
//        a_infoDialog.setVisible(true);

    }

    /**
     * This displays the the SFTP transfer window
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void sftpTransfer(ActionEvent event)
    {
        a_terminal.setDisable(true);
        a_transfer.setVisible(true);
        a_transfer.toFront();
        topMenu.setDisable(true);
        actionBar.setDisable(true);
        logoGrid.setDisable(true);
        connectionList.setDisable(true);

        try
        {
            if (!sftpDirectory.equals(""))
            {
                remoteDirectory.setText(sftpDirectory + "/");
            } else
            {
                remoteDirectory.setText("/home/" + add_uName.getText() + "/");
            }

            if (!sftpTerminalCommand.equals(""))
            {
                if (sftpTerminalCommand.toLowerCase().contains("get "))
                {
                    c_sftpTransferType.getSelectionModel().select("GET");
                    remoteFilename.setText(sftpTerminalCommand.substring(4));
                } 
                else
                {
                    c_sftpTransferType.getSelectionModel().select("PUT");
                    remoteFilename.setText(sftpTerminalCommand.substring(4));
                }

            }

            sftpTerminalCommand = "";

        } catch (Exception e)
        {
        }

    }

    /**
     * This closes the SFTP transfer window
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void cancelTransfer(ActionEvent event)
    {
        a_terminal.setDisable(false);
        a_transfer.setVisible(false);
        topMenu.setDisable(false);
        actionBar.setDisable(false);
        logoGrid.setDisable(false);
        connectionList.setDisable(false);
    }
    
    /**
     * This displays the P2P Server Setup window
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void showP2PServerStart(ActionEvent event) throws Exception
    {
        pageDescription.setText("Start P2P Server");
        a_createp2pServer.toFront();
        a_createp2pServer.setVisible(true);
        
        deleteBtn.setDisable(true);
        editBtn.setDisable(true);
        
        initializeConnectionList(0);
    }

    /**
     * This restarts the P2P server
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void restartP2PServer(ActionEvent event)
    {
        try
        {
            //Alert alert = new Alert(AlertType.CONFIRMATION);
            //alert.setTitle("New Server Session");
            //alert.setHeaderText("Starting a new Server will terminate a currently running server. Are you sure you want to continue?");
            //alert.setContentText("Warning");
            //Optional<ButtonType> option = alert.showAndWait();
            //if (option.get() == null){} 
            //else if (option.get() == ButtonType.OK){
            if (toCloseWindowCheck == false)
            {
                yesNoBtnCheck = false;
                cfmDialog_title.setText("New Server Session");
                cfmDialog_txt1.setText("Starting a new Server will terminate a currently running");
                cfmDialog_txt2.setText("server. Are you sure you want to continue?");
                cfmDialog_txt3.setText("Warning");
                sb.replace(0, sb.length(), "restartP2PServer");
                a_confirmDialog.toFront();
                a_confirmDialog.setVisible(true);

            }
            if (toCloseWindowCheck == true)
            {
                toCloseWindowCheck = false; //reset toCloseWindowCheck to false
                a_confirmDialog.setVisible(false);

                if (yesNoBtnCheck == true)
                {
                    terminateP2PServer(event);
                    startP2PServer(event);
                }
                //else if (option.get() == ButtonType.CANCEL)
                if (yesNoBtnCheck == false)
                {

                }
            }
        } catch (Exception e)
        {

        }
    }

    /**
     * This starts the P2P server
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void startP2PServer(ActionEvent event) throws Exception
    {

        try
        {
            if (!isValidP2PPort(p2pServerPort.getText()))
            {
                //Alert alert = new Alert(AlertType.ERROR);
                //alert.setTitle("Invalid Port Value");
                //alert.setContentText("Port value for P2P connections must be an Integer between 1024 and 65535.");
                //alert.show();
                errDialog_title.setText("Invalid Port Value");
                errDialog_txt1.setText("Port value for P2P connections must be an Integer between");
                errDialog_txt2.setText("1024 and 65535");
                errDialog_txt3.setText("");
                a_errorDialog.toFront();
                a_errorDialog.setVisible(true);

            } else
            {
                if (p2pServerPassword.getText().equals("") || p2pServerPassword.getText() == null)
                {
                    p2pServerPassword.setText("noPassword"); //If password is not specified by user, "noPassword" is used as filler
                }
                infDialog_title.setText("Connection");
                infDialog_txt1.setText("Starting...");
                infDialog_txt2.setText("");
                infDialog_txt3.setText("");
                a_infoDialog.toFront();
                a_infoDialog.setVisible(true);
                p2pServer = new P2PServer(p2pServerIP.getText(), Integer.parseInt(p2pServerPort.getText()), p2pServerPassword.getText(), textArea_terminalOut,
                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);
                //Alert alert = new Alert(AlertType.INFORMATION);
                //alert.setTitle("Server Running");
                //alert.setContentText("Server running at: " + p2pServer.getSocketAddress().getHostAddress()+ " Port=" + p2pServer.getPort());
                //alert.show();
                infDialog_title.setText("Server Running");
                infDialog_txt1.setText("Server running at: " + p2pServer.getSocketAddress().getHostAddress());
                infDialog_txt2.setText("Port=" + p2pServer.getPort());
                infDialog_txt3.setText("");
                a_infoDialog.toFront();
                a_infoDialog.setVisible(true);

                pageDescription.setText("P2P Server");
                a_terminal.toFront();

                a_terminal.setVisible(true);
                button_endServer.setVisible(true);
                button_restartServer.setVisible(true);
                textArea_terminal.setDisable(true);
                button_execute.setDisable(true);
                check_executeWithEnter.setDisable(true);
                button_clearTerminal.setDisable(true);
                button_endConnection.setDisable(true);
                sftpTransferButton.setVisible(false);
                sessionLive = true;

                a_infoDialog.toFront();

                Thread serverThread = new Thread(p2pServer);

                textArea_terminalOut.setText("Server running at: " + p2pServer.getSocketAddress().getHostAddress() + " Port=" + p2pServer.getPort());

                serverThread.start();
            }
        } catch (Exception e)
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("Connection to client lost");
            //alert.setContentText("Connection to the client has been lost. Restart the server to listen for a new client.");
            //alert.show();
            errDialog_title.setText("A server connection error occured");
            errDialog_txt1.setText("The client may have been disconnected.");
            errDialog_txt2.setText("Please check Server connection details or restart the server ");
            errDialog_txt3.setText("to listen for a new client.");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

        }

    }

    /**
     * This terminates the P2P Server
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void terminateP2PServer(ActionEvent event) throws Exception
    {
        if (sessionLive == true)
        {
            p2pServer.endServer();
            a_add.setVisible(true);
            sessionLive = false;

            initializeConnectionList(0);
        }

    }

    /**
     * This detects if P2P is chosen in the connection-type combobox of the Add
     * Connection Page. 
     * 
     * In case P2P is selected, only password authentication is available.
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    void detectP2PSelect(ActionEvent event)
    {
        if (add_cType.getValue().equals("P2P"))
        {
            add_radio_pw.setSelected(true);
            keyBox.setDisable(true);

            add_pwText.setDisable(false);
            add_pw.setDisable(false);
        } else
        {
            keyBox.setDisable(false);

            if (!add_radio_privKey.isSelected())
            {
                add_privateKeyText.setDisable(true);
                add_privateKey.setDisable(true);
                add_passphrase.setDisable(true);
                add_passphraseText.setDisable(true);
                GenAndSaveBtn.setDisable(true);
            }

        }
    }

    /**
     * This handles the Connect button, calling the relevant connect methods 
     * based on the user's choice of connection type.
     * 
     * @param event - JavaFX event
     * @exception JSchException, IOException
     */
    @FXML
    void connectManager(ActionEvent event) throws JSchException, IOException, Exception
    {

        if (add_cType.getValue() == "SSH") //SSH
        {
            if (add_radio_pw.isSelected())
            {
                SSHWithPassword();
            } else
            {
                SSHWithKey();
            }
        } else if (add_cType.getValue() == "SFTP") //SFTP
        {
            if (add_radio_pw.isSelected())
            {
                SFTPWithPassword();
            } else
            {
                SFTPWithKey();
            }
        } else if (add_cType.getValue() == "SCP") //SCP
        {
            if (add_radio_pw.isSelected())
            {
                SCPWithPassword();
            } else
            {
                SCPWithKey();
            }
        } else if (add_cType.getValue() == "P2P") //P2P
        {
            P2PClientConnect();
        }

        button_endServer.setVisible(false);
        textArea_terminal.setDisable(false);
        button_execute.setDisable(false);
        check_executeWithEnter.setDisable(false);
        button_clearTerminal.setDisable(false);
        button_endConnection.setDisable(false);

        historyCombo.getItems().removeAll(add_cType.getItems());
        historyCombo.getItems().addAll("--");
        historyCombo.getSelectionModel().selectFirst();
    }

    /**
     * This performs the P2P client connection.
     * 
     * An instance of P2PClient is initialized and authentication is performed 
     * with the P2P server. In case of successful connection the terminal page
     * is displayed.
     * 
     * @exception JSchException, IOException
     */
    void P2PClientConnect() throws JSchException, IOException, Exception
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {
                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } 
                        else if (!isValidP2PPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value for P2P connections must be an Integer between 1024 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value for P2P connections must be an Integer between");
                            errDialog_txt2.setText("1024 and 65535");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } 
                        else
                        {
                            try
                            {

                                updateProgress(0, 100);
                                if (add_pw.getText().equals("") || add_pw.getText() == null)
                                {
                                    add_pw.setText("noPassword");
                                }

                                p2pClient = new P2PClient(InetAddress.getByName(add_hName.getText()), Integer.parseInt(add_port.getText()), add_uName.getText(), add_pw.getText(), textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);

                                p2pClient.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                String startMessage = "Welcome to Kite SSH terminal.\nType \"terminate\" to end this session.\nType \"help_local\" for additional instructions.\n";
                                terminalOut = terminalOut + startMessage;
                                textArea_terminalOut.setText(terminalOut);

                                if (p2pClient.authenticate()) 
                                {
                                    //Authentication Successful
                                    updateProgress(100, 100);
                                    sessionLive = true;
                                    pageDescription.setText("P2P Terminal");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(true);
                                    textArea_terminal.setText("");
                                    sftpTransferButton.setDisable(true);
                                    sftpTransferButton.setVisible(false);

                                    addBtn.setDisable(true);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!p2pClient.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            p2pClient.writeToFile(connections);
                                        }
                                    }

                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(4);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                //Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                                //Perhaps add a "Connection failed" alert here.
                                
//                                errDialog_title.setText("Connection Failed"); //Not currently required
//                                errDialog_txt1.setText("Connection to the server failed. Please");
//                                errDialog_txt2.setText("ensure all given details are correcct");
//                                errDialog_txt3.setText("and try again.");
//                                a_errorDialog.toFront();
//                                a_errorDialog.setVisible(true);
                                
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This checks if the given value is an integer of the range 1024-65535
     * 
     * This is because ports numbered 1023 and below are reserved and cannot
     * be used for P2P connections.
     * 
     * @param num - User-supplied port value
     * @return true or false 
     */
    boolean isValidP2PPort(String num)
    {
        for (int i = 0; i < num.length(); ++i)
            if (num.charAt(i) < '0' || num.charAt(i) > '9')
                return false;

        int portNum = Integer.parseInt(num);

        if (portNum < 1024 || portNum > 65535)
            return false;

        return true;
    }

    /**
     * This opens the file/directory chooser for the user to use during SCP
     * transfer
     * 
     * @param event - JavaFX event
     */
    @FXML
    void chooseSCPLocalDirectory(ActionEvent event)
    {
        try
        {

            if (scpTransferType.getValue().equals("SCP FROM")) //Directory Choice
            {
                DirectoryChooser chooser = new DirectoryChooser();

                chooser.setTitle("JavaFX Projects");
                chooser.setInitialDirectory(new File("C:/Users/"));
                File selectedDirectory = chooser.showDialog(KiteSSH.stage);

                //System.out.println(selectedDirectory.getAbsolutePath());
                scpLocalFilePath.setText(selectedDirectory.getAbsolutePath());
            } 
            else //File choice
            {
                File file = chooseFile.showOpenDialog(folderImg.getScene().getWindow());
                scpLocalFilePath.setText(file.getParent());
                scpLocalFileName.setText(file.getName());
            }
        } catch (Exception e)
        {

        }
    }

    /**
     * This starts the SCP transfer
     * 
     * @param event - JavaFX event
     */
    @FXML
    void performSCPTransfer(ActionEvent event)
    {
        if (scpLocalFilePath.getText().equals("") || scpLocalFileName.getText().equals("") || scpRemoteFilePath.getText().equals(""))
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("Required Fields Empty");
            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
            //alert.show();
            errDialog_title.setText("Required Fields Empty");
            errDialog_txt1.setText("Please make sure all required fields are filled");
            errDialog_txt2.setText("before proceeding.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

        } else
        {
            try
            {
                if (scpTransferType.getValue() == "SCP TO")
                {
                    String local = scpLocalFilePath.getText() + "\\" + scpLocalFileName.getText();
                    String remote = scpRemoteFilePath.getText();

                    scp1.scpTo(local, remote);
                } else if (scpTransferType.getValue() == "SCP FROM")
                {
                    String local = scpLocalFilePath.getText() + "\\" + scpLocalFileName.getText();
                    String remote = scpRemoteFilePath.getText();

                    scp1.scpFrom(local, remote);
                }
            } catch (Exception e)
            {
            }

        }
    }

    /**
     * This performs SCP authentication with the user-specified Key-Pair
     * 
     * @exceptiom JSchException, IOException
     */
    void SCPWithKey() throws JSchException, IOException
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {
//                        if (add_hName.getText().equals("qq")) //For Testing
//                        {
//                            updateProgress(0, 100);
//                            add_hName.setText("192.168.1.6");
//                            add_uName.setText("pi");
//                            add_port.setText("22");
//
//                            updateProgress(20, 100);
//                        }
                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_privateKey.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } 
                        else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);
                            updateProgress(0, 100);

                        } 
                        else
                        {
                            try
                            {
                                updateProgress(0, 100);
                                scp1 = new SCP(add_hName.getText(), add_uName.getText(), "", add_port.getText(), add_privateKey.getText(), add_passphrase.getText(), textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);

                                scp1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SSH terminal.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (scp1.keyConnectSCP())
                                {
                                    //Authentication Successful
                                    sessionLive = true;
                                    pageDescription.setText("SCP Transfer");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(false);
                                    a_scpControl.setVisible(true);

                                    scpTransferType.getItems().removeAll(scpTransferType.getItems());
                                    scpTransferType.getItems().addAll("SCP TO", "SCP FROM");
                                    scpTransferType.getSelectionModel().selectFirst();

                                    scpLocalFilePath.setText("");
                                    scpLocalFileName.setText("");
                                    scpRemoteFilePath.setText("");

                                    addBtn.setDisable(true);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!scp1.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            scp1.writeToFile(connections);
                                        }
                                    }

                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(3);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This performs SCP authentication with the user-supplied passwor
     * 
     * @exceptiom JSchException, IOException
     */
    void SCPWithPassword() throws IOException, JSchException
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {
                        if (add_hName.getText().equals("qq"))
                        {
                            updateProgress(0, 100);
                            add_hName.setText("192.168.1.6");
                            add_uName.setText("pi");
                            add_port.setText("22");
                            add_pw.setText("123");

                            updateProgress(20, 100);
                        }

                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_pw.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);
                            updateProgress(0, 100);

                        } else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);
                            updateProgress(0, 100);

                        } else
                        {
                            try
                            {
                                updateProgress(0, 100);

                                scp1 = new SCP(add_hName.getText(), add_uName.getText(), add_pw.getText(), add_port.getText(), "", "", textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);

                                scp1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SFTP terminal.\nType \"GET\" or \"PUT\" to initiate an SFTP transfer.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (scp1.passwordConnectSCP())
                                {
                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                sessionLive = true;
                                                pageDescription.setText("SCP Transfer");
                                                a_add.setVisible(false);
                                                a_terminal.setVisible(false);
                                                a_scpControl.setVisible(true);

                                                scpTransferType.getItems().removeAll(scpTransferType.getItems());
                                                scpTransferType.getItems().addAll("SCP TO", "SCP FROM");
                                                scpTransferType.getSelectionModel().selectFirst();

                                                scpLocalFilePath.setText("");
                                                scpLocalFileName.setText("");
                                                scpRemoteFilePath.setText("");

                                                addBtn.setDisable(true);

                                                deleteBtn.setDisable(true);
                                                editBtn.setDisable(true);

                                                if (checkbx_SaveConn.isSelected())
                                                {
                                                    if (!scp1.alreadyExists(connections))
                                                    {
                                                        String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                                        connections.add(currConnectionData);

                                                        scp1.writeToFile(connections);
                                                    }
                                                }

                                                initializeConnectionList(3);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This performs SFTP authentication with the user-specified Key-Pair
     * 
     * @exceptiom JSchException, IOException
     */
    void SFTPWithKey() throws JSchException, IOException
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {

//                        if (add_hName.getText().equals("qq")) //For Testing
//                        {
//                            updateProgress(0, 100);
//                            add_hName.setText("192.168.1.6");
//                            add_uName.setText("pi");
//                            add_port.setText("22");
//
//                            updateProgress(20, 100);
//                        }
                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_privateKey.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else
                        {
                            try
                            {
                                updateProgress(0, 100);
                                sftp1 = new SFTP(add_hName.getText(), add_uName.getText(), "", add_port.getText(), add_privateKey.getText(), add_passphrase.getText(), textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);

                                sftp1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SSH terminal.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (sftp1.keyConnectSFTP())
                                {
                                    sessionLive = true;
                                    pageDescription.setText("SFTP Terminal");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(true);
                                    textArea_terminal.setText("");
                                    sftpTransferButton.setDisable(false);
                                    sftpTransferButton.setVisible(true);
                                    button_endServer.setVisible(false);
                                    button_restartServer.setVisible(false);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!sftp1.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            sftp1.writeToFile(connections);
                                        }
                                    }

                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(2);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This performs SFTP authentication with the user-supplied Password
     * 
     * @exceptiom JSchException, IOException
     */
    void SFTPWithPassword() throws IOException
    {

        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {

//                        if (add_hName.getText().equals("qq")) //For Testing
//                        {
//                            updateProgress(0, 100);
//                            add_hName.setText("192.168.1.6");
//                            add_uName.setText("pi");
//                            add_port.setText("22");
//
//                            updateProgress(20, 100);
//                        }

                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_pw.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else
                        {
                            try
                            {
                                updateProgress(0, 100);

                                sftp1 = new SFTP(add_hName.getText(), add_uName.getText(), add_pw.getText(), add_port.getText(), "", "", textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3,
                                        a_infoDialog, infDialog_title, infDialog_txt1, infDialog_txt2, infDialog_txt3);

                                sftp1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SFTP terminal.\nType \"GET\" or \"PUT\" to initiate an SFTP transfer.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (sftp1.passwordConnectSFTP())
                                {
                                    sessionLive = true;
                                    pageDescription.setText("SFTP Terminal");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(true);
                                    textArea_terminal.setText("");
                                    sftpTransferButton.setDisable(false);
                                    sftpTransferButton.setVisible(true);
                                    button_endServer.setVisible(false);
                                    button_restartServer.setVisible(false);

                                    addBtn.setDisable(true);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!sftp1.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            sftp1.writeToFile(connections);
                                        }
                                    }
                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(2);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });

                                }
                            } catch (Exception ex)
                            {
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);

                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This performs SSH authentication with the user-specified Key-Pair
     * 
     * @exceptiom JSchException, IOException
     */
    void SSHWithKey() throws JSchException, IOException
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {
//                        if (add_hName.getText().equals("qq")) //For Testing
//                        {
//                            updateProgress(0, 100);
//                            add_hName.setText("192.168.1.6");
//                            add_uName.setText("pi");
//                            add_port.setText("22");
//
//                            updateProgress(20, 100);
//                        }
                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_privateKey.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else
                        {
                            try
                            {
                                updateProgress(0, 100);

                                ssh1 = new SSH(add_hName.getText(), add_uName.getText(), "", add_port.getText(), add_privateKey.getText(), add_passphrase.getText(), textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3);

                                ssh1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SSH terminal.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (ssh1.keyConnectSSH())
                                {
                                    sessionLive = true;
                                    pageDescription.setText("SSH Terminal");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(true);
                                    textArea_terminal.setText("");
                                    sftpTransferButton.setDisable(true);
                                    sftpTransferButton.setVisible(false);
                                    button_endServer.setVisible(false);
                                    button_restartServer.setVisible(false);

                                    addBtn.setDisable(true);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!ssh1.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            ssh1.writeToFile(connections);
                                        }
                                    }
                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(1);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This performs SSH authentication with the user-supplied Password
     * 
     * @exceptiom JSchException, IOException
     */
    void SSHWithPassword() throws JSchException, IOException
    {
        a_connectionLoading.toFront();
        a_connectionLoading.setVisible(true);
        Service service = new Service()
        {
            @Override
            protected Task createTask()
            {
                return new Task()
                {
                    @Override
                    protected Object call() throws Exception
                    {

//                        if (add_hName.getText().equals("qq")) //For Testing
//                        {
//                            updateProgress(0, 100);
//                            add_hName.setText("192.168.1.6");
//                            add_uName.setText("pi");
//                            add_port.setText("22");
//
//                            updateProgress(20, 100);
//                        }
                        if (add_hName.getText().equals("") || add_uName.getText().equals("") || add_port.getText().equals("") || add_pw.getText().equals(""))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Required Fields Empty");
                            //alert.setContentText("Please make sure all required fields are filled before proceeding.");
                            //alert.show();
                            errDialog_title.setText("Required Fields Empty");
                            errDialog_txt1.setText("Please make sure all required fields are filled");
                            errDialog_txt2.setText("before proceeding.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else if (!isValidPort(add_port.getText()))
                        {
                            //Alert alert = new Alert(AlertType.ERROR);
                            //alert.setTitle("Invalid Port Value");
                            //alert.setContentText("Port value must be an Integer between 0 and 65535.");
                            //alert.show();
                            errDialog_title.setText("Invalid Port Value");
                            errDialog_txt1.setText("Port value must be an Integer between");
                            errDialog_txt2.setText("0 and 65535.");
                            errDialog_txt3.setText("");
                            a_errorDialog.toFront();
                            a_errorDialog.setVisible(true);

                            updateProgress(0, 100);

                        } else
                        {
                            try
                            {
                                updateProgress(0, 100);

                                ssh1 = new SSH(add_hName.getText(), add_uName.getText(), add_pw.getText(), add_port.getText(), "", "", textArea_terminalOut,
                                        a_errorDialog, errDialog_title, errDialog_txt1, errDialog_txt2, errDialog_txt3);

                                ssh1.progressProperty().addListener((obs, oldProgress, newProgress)
                                        -> updateProgress(newProgress.doubleValue(), 1));

                                String terminalOut = add_uName.getText() + "@" + add_hName.getText() + ":\n";
                                terminalOut = terminalOut + "Welcome to Kite SSH terminal.\nType \"terminate\" to end this session.\n";
                                textArea_terminalOut.setText(terminalOut);

                                if (ssh1.passwordConnectSSH())
                                {
                                    sessionLive = true;
                                    pageDescription.setText("SSH Terminal");
                                    a_add.setVisible(false);
                                    a_terminal.setVisible(true);
                                    textArea_terminal.setText("");
                                    sftpTransferButton.setDisable(true);
                                    sftpTransferButton.setVisible(false);
                                    button_endServer.setVisible(false);
                                    button_restartServer.setVisible(false);

                                    addBtn.setDisable(true);

                                    deleteBtn.setDisable(true);
                                    editBtn.setDisable(true);

                                    if (checkbx_SaveConn.isSelected())
                                    {
                                        if (!ssh1.alreadyExists(connections))
                                        {
                                            String currConnectionData = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText() + ":";

                                            connections.add(currConnectionData);

                                            ssh1.writeToFile(connections);
                                        }
                                    }
                                    Platform.runLater(new Runnable()
                                    {
                                        @Override
                                        public void run()
                                        {
                                            try
                                            {
                                                initializeConnectionList(1);
                                            } catch (Exception e)
                                            {

                                            }
                                        }
                                    });
                                }
                            } catch (Exception ex)
                            {
                                //catch interrupted exception
                                Logger.getLogger(KiteSSHGUIController.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        return null;
                    }
                };
            }
        };
        pBar_load.progressProperty().bind(service.progressProperty());
        service.start();
    }

    /**
     * This checks if the given port value is an integer  within the range 0-65535
     * 
     * @param num - User-supplied port value
     * @return - true or false
     */ 
    boolean isValidPort(String num)
    {
        for (int i = 0; i < num.length(); ++i)
            if (num.charAt(i) < '0' || num.charAt(i) > '9')
                return false;

        int portNum = Integer.parseInt(num);

        if (portNum < 0 || portNum > 65535)
            return false;

        return true;
    }

    /**
     * This handles actions on the GUI menu buttons, namely the add, delete and
     * edit buttons
     * 
     * @param event - JavaFX Mouse event
     */ 
    @FXML
    private void handleMenuButtonAction(MouseEvent event)
    {
        if (sessionLive == true)
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("Session Live");
            //alert.setContentText("You are currently in a connected session. Please end the session before proceeding.");
            //alert.show();
            errDialog_title.setText("Session Live");
            errDialog_txt1.setText("You are currently in a connected session. Please end the");
            errDialog_txt2.setText("session before proceeding.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

            return;
        }

        if (event.getSource() == addBtn)
        {
            a_home.setVisible(false);
            a_add.setVisible(true);
            a_add.toFront();
            a_terminal.setVisible(false);
            a_createp2pServer.setVisible(false);
            //a_delete.setVisible(false);
            //a_edit.setVisible(false);

            pageDescription.setText("Add new Connection Details");

            passwordBox.setDisable(false);
            keyBox.setDisable(false);

            add_hName.setText("");
            add_uName.setText("");
            add_port.setText("22");
            add_pw.setText("");
            add_privateKey.setText("");

            add_hName.setEditable(true);
            add_uName.setEditable(true);
            add_port.setEditable(true);

            deleteBtn.setDisable(true);
            editBtn.setDisable(true);

            colorButtonsDefault();
        } else if (event.getSource() == deleteBtn)
        {
            //a_home.setVisible(false);
            //a_add.setVisible(false);
            //a_delete.setVisible(true);
            //a_edit.setVisible(false);

        } else if (event.getSource() == editBtn)
        {
            //a_home.setVisible(false);
            //a_add.setVisible(false);
            //a_delete.setVisible(false);
            //a_edit.setVisible(true);

        } else if (event.getSource() == serverStartBtn)
        {
            ActionEvent event1 = new ActionEvent();
            try
            {
                showP2PServerStart(event1);
            } 
            catch (Exception e)
            {
               
            }
        }
    }

    /**
     * This handles actions on the GUI radio buttons, namely the Password and 
     * Private Key authentication type buttons. 
     * 
     * If one radio button is clicked the other field will be disabled and 
     * vice versa
     * 
     * @param event - JavaFX Mouse event
     */ 
    @FXML
    private void handleRadioButton(MouseEvent event)
    {
        //buttons: add_radio_pw, add_radio_privKey
        //rectangle covers: add_coverPW,add_coverPrivKey
        if (add_radio_pw.isSelected())
        {
            add_pwText.setDisable(false);
            add_pw.setDisable(false);

            add_privateKeyText.setDisable(true);
            add_privateKey.setDisable(true);
            add_passphrase.setDisable(true);
            add_passphraseText.setDisable(true);
            GenAndSaveBtn.setDisable(true);

            //add_coverPW.setVisible(false);
            //add_coverPrivKey.setVisible(true);
        } else if (add_radio_privKey.isSelected())
        {
            add_privateKeyText.setDisable(false);
            add_privateKey.setDisable(false);
            add_passphrase.setDisable(false);
            add_passphraseText.setDisable(false);
            GenAndSaveBtn.setDisable(false);

            add_pwText.setDisable(true);
            add_pw.setDisable(true);
            //add_coverPW.setVisible(true);
            //add_coverPrivKey.setVisible(false);
        } else
        {
        }
    }

    /**
     * This displays the file chooser for the Private Key file selection 
     * 
     * @param event - JavaFX Mouse event
     */ 
    @FXML
    private void handleChooseFile(MouseEvent event)
    {
        try
        {
            if (event.getTarget() == folderImg)
            {
                File file = chooseFile.showOpenDialog(folderImg.getScene().getWindow());
                add_privateKey.setText(file.getAbsolutePath());
            }
        } catch (Exception e)
        {

        }
    }

    //generate and save function
    //@FXML
    //private void genAndSaveButton(MouseEvent event)
    //{
    //button: GenAndSaveBtn
    //code to illustrate generate and save key details
    //when keys have been saved, the anchorpane, a_keySaved, will display
    //a_keySaved.setVisible(true);
    //}
    //okBtn
    
    /**
     * This handles the OK button press in the various alerts displayed during 
     * the run-time of this app.
     * 
     * @param event - JavaFX event
     * @exception JSchException, SftpException, IOException
     */ 
    @FXML
    private void handleOkButton(ActionEvent event) throws JSchException, SftpException, IOException

    {
        if (a_connectionLoading.isVisible() == true)
        {
            a_connectionLoading.setVisible(false);
        } else if (a_errorDialog.isVisible() == true)
        {
            a_errorDialog.setVisible(false);
        } else if (a_infoDialog.isVisible() == true)
        {
            a_infoDialog.setVisible(false);
        }

    }

    /**
     * This handles the YES button press in the various alerts displayed during 
     * the run-time of this app.
     * 
     * @param event - JavaFX event
     * @exception FileNotFoundException, IOException
     */ 
    @FXML
    private void handleYesButton(ActionEvent event) throws FileNotFoundException, IOException
    {
        yesNoBtnCheck = true;
        toCloseWindowCheck = true;

        if (a_confirmDialog.isVisible() == true)
        {
            if (sb.toString().equals("terminateConnection"))
            {
                terminateConnection(event);
            } else if (sb.toString().equals("handleCloseApp"))
            {
                handleCloseApp(event);
            } else if (sb.toString().equals("saveChanges"))
            {
                saveChanges(event);
            } else if (sb.toString().equals("deleteConnection"))
            {
                deleteConnection(event);
            } else if (sb.toString().equals("returnHome"))
            {
                returnHome(event);
            } else if (sb.toString().equals("restartP2PServer"))
            {
                restartP2PServer(event);
            }
        }
    }

    /**
     * This handles the NO button press in the various alerts displayed during 
     * the run-time of this app.
     * 
     * @param event - JavaFX event
     * @exception FileNotFoundException, IOException
     */ 
    @FXML
    private void handleNoButton(ActionEvent event) throws FileNotFoundException, IOException
    {
        yesNoBtnCheck = false;
        toCloseWindowCheck = true;
        if (a_confirmDialog.isVisible() == true)
        {
            if (sb.toString().equals("terminateConnection"))
            {
                terminateConnection(event);
            } else if (sb.toString().equals("handleCloseApp"))
            {
                handleCloseApp(event);
            } else if (sb.toString().equals("saveChanges"))
            {
                saveChanges(event);
            } else if (sb.toString().equals("deleteConnection"))
            {
                deleteConnection(event);
            } else if (sb.toString().equals("returnHome"))
            {
                returnHome(event);
            } else if (sb.toString().equals("restartP2PServer"))
            {
                restartP2PServer(event);
            }
        }

    }

    /*
    //Add page, connect and cancel button
    @FXML
    private void handleAddPageButtonAction(MouseEvent event)
    {
        boolean b = false;
        if (event.getSource() == connectBtn)
        {
            //add_cType, add_hName,add_port, add_privateKey, add_pw
            b = add_cType.getValue() != null && !add_cType.getValue().toString().isEmpty()
                    && add_hName != null && !add_hName.toString().isEmpty()
                    && add_port != null && !add_port.toString().isEmpty()
                    && (add_privateKey != null && !add_privateKey.toString().isEmpty()
                    || add_pw != null && !add_pw.toString().isEmpty());

            //b is true if all necessary parts are completed
            if (b)
            {

                //if checkbox is checked
                if (checkbx_SaveConn.isSelected())
                {
                    //code to illustrate save connection details
                }
            }
        }
    }*/
    
    /**
     * This handles the Minimize button press in the GUI. 
     * When called, the application is minimized.
     * 
     * @param event - JavaFX Mouse event
     */ 
    @FXML
    private void handleMinimizeButton(MouseEvent event)
    {
        Stage stage1 = (Stage) baseAnchorPane.getScene().getWindow();
        stage1.setIconified(true);
    }

    /**
     * This handles the Maximize button press in the GUI. 
     * When called, the application is maximized if not already maximized. 
     * If the app is in a maximized state, it is returned to original size.
     * 
     * @param event - JavaFX Mouse event
     */ 
    @FXML
    private void handleResizeAppButton(MouseEvent event)
    {
        Stage stage1 = (Stage) baseAnchorPane.getScene().getWindow();
        if (stage1.isMaximized())
        {
            stage1.setMaximized(false);
        } else
        {
            stage1.setMaximized(true);
        }
    }

    /*
    @FXML
    private void handleButtonAction(ActionEvent event) {
        System.out.println("You clicked me!");
        label.setText("Hello World!");
    }*/
    
    /**
     * This handles the Close button press in the GUI. 
     * When called, the application is terminated completely
     * In case of running operations, a confirmation is shown to the user.
     * 
     * @param event - JavaFX event
     */ 
    @FXML
    private void handleCloseApp(ActionEvent event)
    {
        if (sessionLive == true)
        {
            //Alert alert = new Alert(AlertType.CONFIRMATION);
            //alert.setTitle("Warning");
            //alert.setHeaderText("You are about to exit during a connected session. Unsaved data may be lost. Are you sure you want to proceed?");
            //alert.setContentText("Exit during connection");
            //Optional<ButtonType> option = alert.showAndWait();
            //if (option.get() == null){}
            if (toCloseWindowCheck == false)
            {
                yesNoBtnCheck = false;
                cfmDialog_title.setText("Warning");
                cfmDialog_txt1.setText("You are about to exit during a connected session. Unsaved");
                cfmDialog_txt2.setText("data may be lost. Are you sure you want to proceed?");
                cfmDialog_txt3.setText("Exit during connection");
                sb.replace(0, sb.length(), "handleCloseApp");

                a_confirmDialog.toFront();
                a_confirmDialog.setVisible(true);

            }
            if (toCloseWindowCheck == true)
            {
                toCloseWindowCheck = false; //reset toCloseWindowCheck to false
                a_confirmDialog.setVisible(false);

                //else if (option.get() == ButtonType.OK)
                if (yesNoBtnCheck == true)
                {
                    System.exit(0);
                } //else if (option.get() == ButtonType.CANCEL)
                else if (yesNoBtnCheck == false)
                {

                }
            }
        } else if (a_add.isVisible() == true)
        {
            if (toCloseWindowCheck == false)
            {
                cfmDialog_title.setText("Close KiteSSH");
                cfmDialog_txt1.setText("Are you sure you want to close KiteSSH?");
                cfmDialog_txt2.setText("Any unsaved changes will be lost.");
                cfmDialog_txt3.setText("");
                sb.replace(0, sb.length(), "handleCloseApp");

                a_confirmDialog.toFront();
                a_confirmDialog.setVisible(true);

            }
            if (toCloseWindowCheck == true)
            {
                toCloseWindowCheck = false;
                a_confirmDialog.setVisible(false);

                if (yesNoBtnCheck == true)
                {
                    System.exit(0);
                } else if (yesNoBtnCheck == false)
                {
                }
            }
        } else
        {
            System.exit(0);
        }

    }

    /**
     * This handles the Save Changes button press in the edit connection page
     * When called, the changed connection details are saved and written to the 
     * "savedConnections.txt" file.
     * 
     * @param event - JavaFX event
     * @exception FileNotFoundException, IOException
     * 
     */ 
    @FXML
    public void saveChanges(ActionEvent event) throws FileNotFoundException, IOException
    {
        if (!currentButton.getText().equals(""))
        {
            if (!currentButton.getText().equals(""))
            {
                //Alert alert = new Alert(AlertType.CONFIRMATION);
                //alert.setTitle("Warning");
                //alert.setHeaderText("You are about to ovewrite the details of a saved connection. Are you sure you want to proceed?");
                //alert.setContentText("This action is permanent.");
                //Optional<ButtonType> option = alert.showAndWait();
                //if (option.get() == null){
                //} else if (option.get() == ButtonType.OK)
                if (toCloseWindowCheck == false)
                {
                    yesNoBtnCheck = false;
                    cfmDialog_title.setText("Warning");
                    cfmDialog_txt1.setText("You are about to ovewrite the details of a saved");
                    cfmDialog_txt2.setText("connection. Are you sure you want to proceed?");
                    cfmDialog_txt3.setText("This action is permanent.");
                    sb.replace(0, sb.length(), "saveChanges");
                    a_confirmDialog.toFront();
                    a_confirmDialog.setVisible(true);

                }
                if (toCloseWindowCheck == true)
                {
                    toCloseWindowCheck = false;
                    a_confirmDialog.setVisible(false);

                    if (yesNoBtnCheck == true)
                    {
                        changedConnection = add_hName.getText() + ":" + add_uName.getText() + ":" + add_port.getText();

                        int id = Integer.parseInt(currentButton.getId());
                        connections.set(id, changedConnection);

                        currentButton.setText("");

                        writeAllConnectionsToFile();
                        initializeConnectionList(5);

                        checkbx_SaveConn.setVisible(true);
                        connectBtn.setVisible(true);
                        cancelBtn.setVisible(true);
                        saveChangesBtn.setVisible(false);
                        
                        addBtn.setDisable(false);
                        serverStartBtn.setDisable(false);

                        checkbx_SaveConn.setDisable(false);
                        connectBtn.setDisable(false);
                        cancelBtn.setDisable(false);
                        saveChangesBtn.setDisable(true);

                        add_hName.setEditable(false);
                        add_uName.setEditable(false);
                        add_port.setEditable(false);

                        //add_pw.setDisable(false);
                        passwordBox.setDisable(false);
                        keyBox.setDisable(false);
                    } //else if (option.get() == ButtonType.CANCEL)
                    else if (yesNoBtnCheck == false)
                    {

                    }
                }
            }
        }
    }

    /**
     * This handles the Edit Connection button press in the edit connection page
     * When called, the fields of the currently displayed connection are made
     * editable so they can be changed by the user.
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    public void editConnection(ActionEvent event)
    {
        checkbx_SaveConn.setVisible(false);
        connectBtn.setVisible(false);
        cancelBtn.setVisible(false);
        saveChangesBtn.setVisible(true);

        checkbx_SaveConn.setDisable(true);
        connectBtn.setDisable(true);
        cancelBtn.setDisable(true);
        saveChangesBtn.setDisable(false);
        addBtn.setDisable(true);
        serverStartBtn.setDisable(true);

        add_hName.setEditable(true);
        add_uName.setEditable(true);
        add_port.setEditable(true);

        //add_pw.setDisable(true);
        passwordBox.setDisable(true);
        keyBox.setDisable(true);

    }

    /**
     * This handles the Delete Connection button press in the edit connection page
     * When called, the currently selected connection is deleted and the change 
     * is saved in the "saveConnections.txt" file.
     * 
     * @param event - JavaFX event
     * 
     */
    @FXML
    public void deleteConnection(ActionEvent event) throws IOException
    {
        if (!currentButton.getText().equals(""))
        {
            //Alert alert = new Alert(AlertType.CONFIRMATION);
            //alert.setTitle("Warning");
            //alert.setHeaderText("You are about to delete a saved connection. Are you sure you want to proceed?");
            //alert.setContentText("This action is permanent.");
            //Optional<ButtonType> option = alert.showAndWait();
            //if (option.get() == null){} 
            //else if (option.get() == ButtonType.OK)
            if (toCloseWindowCheck == false)
            {
                yesNoBtnCheck = false;
                cfmDialog_title.setText("Warning");
                cfmDialog_txt1.setText("You are about to delete a saved connection. Are you sure");
                cfmDialog_txt2.setText("you want to proceed?");
                cfmDialog_txt3.setText("This action is permanent.");
                sb.replace(0, sb.length(), "deleteConnection");
                a_confirmDialog.toFront();
                a_confirmDialog.setVisible(true);

            }
            if (toCloseWindowCheck == true)
            {
                toCloseWindowCheck = false;
                a_confirmDialog.setVisible(false);

                if (yesNoBtnCheck == true)
                {
                    int id = Integer.parseInt(currentButton.getId());
                    connections.remove(id);
                    
                    writeAllConnectionsToFile();
                    initializeConnectionList(0);
                } //else if (option.get() == ButtonType.CANCEL)
                else if (yesNoBtnCheck == false)
                {

                }
            }
        }
    }

    /**
     * This writes all connections in the list connections to the file 
     * "savedConnections.txt"
     * 
     * @exception IOException
     * 
     */
    public void writeAllConnectionsToFile() throws IOException
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
            infDialog_title.setText("Connection Saved");
            infDialog_txt1.setText("Connection have been saved.");
            infDialog_txt2.setText("");
            infDialog_txt3.setText("");
            a_infoDialog.toFront();
            a_infoDialog.setVisible(true);

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
     * This displays the details of the selected connection
     * The selected button is colored: #6666ff
     * 
     * @param event - JavaFX event
     * 
     */
    public void showConnection(ActionEvent event)
    {
        if (sessionLive == true)
        {
            //Alert alert = new Alert(AlertType.ERROR);
            //alert.setTitle("Session Live");
            //alert.setContentText("You are currently in a connected session. Please end the session before proceeding.");
            //alert.show();
            errDialog_title.setText("Session Live");
            errDialog_txt1.setText("You are currently in a connected session. Please end the");
            errDialog_txt2.setText("session before proceeding.");
            errDialog_txt3.setText("");
            a_errorDialog.toFront();
            a_errorDialog.setVisible(true);

            return;
        }

        try
        {
            colorButtonsDefault();

            pageDescription.setText("Saved Connection");

            currentButton = ((Button) event.getSource());

            int id = Integer.parseInt(currentButton.getId());
            currentButton.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");

            a_add.toFront();
            a_add.setVisible(true);

            String data[] = connections.get(id).split(":");

            add_hName.setText(data[0]);
            add_uName.setText(data[1]);
            add_port.setText(data[2]);
            add_pw.setText("");

            passwordBox.setDisable(false);
            keyBox.setDisable(false);

            deleteBtn.setDisable(false);
            editBtn.setDisable(false);

            add_hName.setEditable(false);
            add_uName.setEditable(false);
            add_port.setEditable(false);
        } catch (Exception e)
        {

        }
    }

    /**
     * This colors all buttons in the buttonList to the default color of #00e6e6
     *  
     */
    public void colorButtonsDefault()
    {
        for (int i = 0; i < buttonList.size(); ++i)
        {
            buttonList.get(i).setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
        }
    }

    /**
     * This initializes the connectionList by reading from the file 
     * "savedConnections.txt"
     * 
     * @param form - The type of connection currently live:
     *                  0 - No connection is live
     *                  1 - SSH
     *                  2 - SFTP
     *                  3 - SCP
     *                  4 - P2P
     *                  5 - Connection Changed
     * 
     * The currently live connection is colored: #25cc00
     * 
     * @exception IOException
     * 
     */
    public void initializeConnectionList(int form) throws FileNotFoundException
    {
        connectionList.getChildren().clear();

        buttonList = new ArrayList<Button>();

        connections.clear();
        
        try
        {
            File file = new File("resources/savedConnections.txt");    //creates a new file instance  
            FileReader fileReader = new FileReader(file);   //reads the file  
            BufferedReader br = new BufferedReader(fileReader);  //creates a buffering character input stream  

            int buttonId = 0;

            String line;
            while ((line = br.readLine()) != null)
            {
                connections.add(line);

                String connectionData[] = line.split(":");

                String connectionInfo = connectionData[1] + "@" + connectionData[0] + " : " + connectionData[2];

                Button b1 = new Button();
                b1.setId(Integer.toString(buttonId));
                ++buttonId;

                b1.setOnAction(new EventHandler<ActionEvent>()
                {
                    @Override
                    public void handle(ActionEvent event)
                    {
                        showConnection(event);
                    }
                });

                if (form == 0) //No Connection
                {
                    b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                } 
                else if (form == 1) //SSH
                {
                    if (ssh1.match(line))
                    {
                        //b1.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                        b1.setStyle("-fx-background-color:  #25cc00;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");
                    } else
                    {
                        b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                    }
                } 
                else if (form == 2) //SFTP
                {
                    if (sftp1.match(line))
                    {
                        //b1.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                        b1.setStyle("-fx-background-color:  #25cc00;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");
                    } else
                    {
                        b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                    }
                } 
                else if (form == 3) //SCP
                {
                    if (scp1.match(line))
                    {
                        //b1.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                        b1.setStyle("-fx-background-color:  #25cc00;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");
                    } else
                    {
                        b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                    }
                } 
                else if (form == 4) //P2P
                {
                    if (p2pClient.match(line))
                    {
                        //b1.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                        b1.setStyle("-fx-background-color:  #25cc00;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");
                    } else
                    {
                        b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                    }
                } 
                else if (form == 5) //Changed Connection
                {
                    if (changedConnection.equals(line))
                    {
                        b1.setStyle("-fx-background-color:  #6666ff;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;" + "-fx-text-fill: white;");
                    } else
                    {
                        b1.setStyle("-fx-background-color: #00e6e6;" + "-fx-border-color:  #666666;" + "-fx-font-size:14;");
                    }
                }

                b1.setMinWidth(connectionList.getPrefWidth());
                b1.setPrefHeight(39);
                b1.setText(connectionInfo);
                buttonList.add(b1);
            }
            fileReader.close();
        } catch (Exception e)
        {

        }

        for (int i = 0; i < buttonList.size(); ++i)
        {
            connectionList.getChildren().add(buttonList.get(i));
        }
    }


    /**
     * This initializes all the GUI elements of the application.
     * It is implicitly called during the start of the application.
     * 
     * @param url
     * @param rb
     * 
     */    
    @Override
    public void initialize(URL url, ResourceBundle rb)
    {
        try
        {
            currentButton.setText("");

            //combobox for connection type in Add page
            add_cType.getItems().removeAll(add_cType.getItems());
            add_cType.getItems().addAll("SSH", "SFTP", "SCP", "P2P");
            add_cType.getSelectionModel().selectFirst();

            a_home.setVisible(true);
            a_add.setVisible(false);
            a_terminal.setVisible(false);
            button_endServer.setVisible(false);
            button_restartServer.setVisible(false);
            a_scpControl.setVisible(false);
            a_transfer.setVisible(false);
            a_SSHKeyGen.setVisible(false);
            a_createp2pServer.setVisible(false);
            c_sftpTransferType.getItems().addAll("GET", "PUT");
            c_sftpTransferType.getSelectionModel().selectFirst();
            saveChangesBtn.setVisible(false);

            initializeConnectionList(0);

            deleteBtn.setDisable(true);
            editBtn.setDisable(true);

            saveChangesBtn.setDisable(true);

            //toggle group
            ToggleGroup tog = new ToggleGroup();
            add_radio_pw.setToggleGroup(tog);
            add_radio_privKey.setToggleGroup(tog);
        } catch (Exception e)
        {

        }

    }

}
