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

import javafx.application.Application;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.Node;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;

/**
 * This class is the primary class of the KiteSSH Application
 * It calls the applications FXML file and it's controller
 *
 * This is the first class to execute at application startup
 */
public class KiteSSH extends Application {
    
    
    private double xPos = 0;
    private double yPos = 0;
    //current cursor diaplay
    private Cursor cursorEvent = Cursor.DEFAULT;
    
    private boolean toResize = true;
    
    //resizing part of the application
    private int border = 4;
    
    private double startDragPosX = 0;
    private double startDragPosY = 0;
    private double screenOffsetX = 0;
    private double screenOffsetY = 0;
    
    private double minWidth = 1;
    private double maxWidth = Double.MAX_VALUE;
    private double minHeight = 1;
    private double maxHeight = Double.MAX_VALUE;
    protected static Stage stage;  
    
    @Override
    public void start(Stage stage1) throws Exception {
        stage = stage1;
        Parent root = FXMLLoader.load(getClass().getResource("KiteSSHGUI.fxml"));
        stage.initStyle(StageStyle.UNDECORATED);
        
        stage.getIcons().add(new Image("file:src/kiteSSHicon.png"));
        
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
        
        EventHandler<MouseEvent> mouseMoveHandler = new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if(event.getEventType() == MouseEvent.MOUSE_MOVED) {
                    double xPos_moved = event.getSceneX();
                    double yPos_moved = event.getSceneY();
                    double sceneWidth = scene.getWidth();
                    double sceneHeight = scene.getHeight();
                    if(stage.isMaximized()==false){
                        //NorthWest
                        if (xPos_moved < border && yPos_moved < border) {
                            cursorEvent = Cursor.NW_RESIZE;
                        }
                        //NorthEast
                        else if (xPos_moved > sceneWidth - border && yPos_moved < border) {
                            cursorEvent = Cursor.NE_RESIZE;
                        }
                        //SouthWest
                        else if (xPos_moved < border && yPos_moved > sceneHeight - border) {
                            cursorEvent = Cursor.SW_RESIZE;
                        }
                        //SouthEast
                        else if (xPos_moved > sceneWidth - border && yPos_moved > sceneHeight - border) {
                            cursorEvent = Cursor.SE_RESIZE;
                        }
                        //West
                        else if (xPos_moved < border) {
                            cursorEvent = Cursor.W_RESIZE;
                        }
                        //North
                        else if (yPos_moved < border) {
                            cursorEvent = Cursor.N_RESIZE;
                        }
                        //East
                        else if (xPos_moved > sceneWidth - border) {
                            cursorEvent = Cursor.E_RESIZE;
                        }
                        //South
                        else if (yPos_moved > sceneHeight - border) {
                            cursorEvent = Cursor.S_RESIZE;
                        }
                        //Other areas not on the border of the app
                        else {
                            cursorEvent = Cursor.DEFAULT;
                        }
                        scene.setCursor(cursorEvent);
                    }
                }
            }
        };

        EventHandler<MouseEvent> mouseExitedHandler = new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if(event.getEventType() == MouseEvent.MOUSE_EXITED) {
                    scene.setCursor(Cursor.DEFAULT);
                }
            }
        };

        
        EventHandler<MouseEvent> mouseExitTargetHandler = new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event){
                if(event.getEventType() == MouseEvent.MOUSE_EXITED_TARGET) {
                    scene.setCursor(Cursor.DEFAULT);
                }
            }
        };

        EventHandler<MouseEvent> mousePressedHandler = new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if(event.getEventType() == MouseEvent.MOUSE_PRESSED) {
                    double xPos_moved = event.getSceneX();
                    double yPos_moved = event.getSceneY();
                    startDragPosX = stage.getWidth() - xPos_moved;
                    startDragPosY = stage.getHeight() - yPos_moved;
                    if(Cursor.DEFAULT.equals(cursorEvent)) {
                        toResize = false;
                        screenOffsetX = stage.getX() - event.getScreenX();
                        screenOffsetY = stage.getY() - event.getScreenY();
                    }
                }
            }
        };

        EventHandler<MouseEvent> mouseDraggedHandler = new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if(event.getEventType() == MouseEvent.MOUSE_DRAGGED) {
                    double xPos_moved = event.getSceneX();
                    double yPos_moved = event.getSceneY();

                    double minHeight = 0;
                    double height = 0;
                    double minWidth = 0;
                    double width = 0;
                    if(!Cursor.DEFAULT.equals(cursorEvent)){
                        toResize = true;
                        //set height
                        if(!Cursor.W_RESIZE.equals(cursorEvent) && !Cursor.E_RESIZE.equals(cursorEvent)) {
                            minHeight = stage.getMinHeight();
                            if(!(minHeight > (border * 2))){
                                minHeight = border * 2;
                            }
                            if(Cursor.NW_RESIZE.equals(cursorEvent) || Cursor.N_RESIZE.equals(cursorEvent)
                                    || Cursor.NE_RESIZE.equals(cursorEvent)) {
                                if (stage.getHeight() > minHeight || yPos_moved < 0) {
                                    height = stage.getY() - event.getScreenY() + stage.getHeight();
                                    if(height > maxHeight) {
                                        height = maxHeight;
                                    }
                                    if(height < minHeight) {
                                        height = minHeight;
                                    }
                                    stage.setHeight(height);
                                    stage.setY(event.getScreenY());
                                }
                            } else if (stage.getHeight() > minHeight || yPos_moved + startDragPosY - stage.getHeight() > 0) {
                                height = yPos_moved + startDragPosY;
                                if(height > maxHeight) {
                                    height = maxHeight;
                                }
                                if(height < minHeight) {
                                    height = minHeight;
                                }
                                stage.setHeight(height);
                            }
                        }
                    }
                    if (!Cursor.N_RESIZE.equals(cursorEvent) && !Cursor.S_RESIZE.equals(cursorEvent)) {
                            minWidth = stage.getMinWidth();
                            if(!(minWidth > (border * 2)) ){
                                minWidth = border * 2;
                            }
                            if (Cursor.NW_RESIZE.equals(cursorEvent) || Cursor.W_RESIZE.equals(cursorEvent)
                                    || Cursor.SW_RESIZE.equals(cursorEvent)) {
                                if (stage.getWidth() > minWidth || xPos_moved < 0) {
                                    width = stage.getX() - event.getScreenX() + stage.getWidth();
                                    if(width > maxWidth) {
                                        width = maxWidth;
                                    }
                                    if(width < minWidth) {
                                        width = minWidth;
                                    }
                                    stage.setWidth(width);
                                    stage.setX(event.getScreenX());
                                }
                            } else {
                                if (stage.getWidth() > minWidth || xPos_moved + startDragPosX - stage.getWidth() > 0) {
                                    width = xPos_moved + startDragPosX;
                                    if(width > maxWidth) {
                                        width = maxWidth;
                                    }
                                    if(width < minWidth) {
                                        width = minWidth;
                                    }
                                    stage.setWidth(width);
                                }
                            }
                        }
                        toResize = false;


                    if(Cursor.DEFAULT.equals(cursorEvent) && toResize == false) {
                        stage.setX(event.getScreenX() + screenOffsetX);
                        stage.setY(event.getScreenY() + screenOffsetY);
                    }
                }
            }
        };

        
        stage.getScene().addEventHandler(MouseEvent.MOUSE_EXITED_TARGET,mouseExitTargetHandler);
        stage.getScene().addEventHandler(MouseEvent.MOUSE_MOVED,mouseMoveHandler);
        stage.getScene().addEventHandler(MouseEvent.MOUSE_EXITED,mouseExitedHandler);
        stage.getScene().addEventHandler(MouseEvent.MOUSE_PRESSED,mousePressedHandler);
        stage.getScene().addEventHandler(MouseEvent.MOUSE_DRAGGED,mouseDraggedHandler);

        ObservableList<Node> children = stage.getScene().getRoot().getChildrenUnmodifiable();
        for (Node child : children)
        {
            child.addEventHandler(MouseEvent.MOUSE_MOVED,mouseMoveHandler);
            child.addEventHandler(MouseEvent.MOUSE_EXITED,mouseExitedHandler);
            child.addEventHandler(MouseEvent.MOUSE_EXITED_TARGET,mouseExitTargetHandler);
            child.addEventHandler(MouseEvent.MOUSE_PRESSED,mousePressedHandler);
            child.addEventHandler(MouseEvent.MOUSE_DRAGGED,mouseDraggedHandler);
        }

    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }
    
}
