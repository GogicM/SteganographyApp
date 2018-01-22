package controllers;

import java.awt.Desktop;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.imageio.ImageIO;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;
import server.ServerThread;
import steganography.Steganography;

public class UserPanelController {


    private String fileName;
    private String userName;
    private String selectedUsername;
    private BufferedImage image = null;
    private Steganography steganography;
    private File imgFile;
    private final Desktop desktop = Desktop.getDesktop();

    private static final int PORT_NUMBER = 9999;
    private static String PATH = "src/server/users";
    
    protected static String newFileData;

    protected static ObservableList<String> data = FXCollections.observableArrayList();

    @FXML
    ListView<String> list;
    @FXML
    private Button sendMessageButton;
    @FXML
    private Button showNewButton;
    @FXML
    private Button browsePictureButton;

//    @FXML
//    private Button showLogsButton;
    @FXML
    private TextArea writeNewMessage;
    @FXML
    private TextArea viewNewMessages;
    @FXML
    private Label newMessagesLabel;
    @FXML
    private void initialize() {
    	
    	steganography = new Steganography();
    	viewNewMessages.setVisible(false);
    	try {
    		File f = new File("src/controllers/users.txt");
    		BufferedReader bReader = new BufferedReader(new FileReader(f));
    		String s = null;
    		while ((s = bReader.readLine()) != null) {
    			String uName = s.split("#")[0];
    			data.add(uName);
    		}
    		bReader.close();
    	} catch(IOException e) {
    		e.printStackTrace();
    	}
        list.setItems(data);
        userName = SignInController.uName;

        list.getSelectionModel().selectedItemProperty().addListener(
                new ChangeListener<String>() {
            public void changed(ObservableValue<? extends String> ov,
                    String old_val, String new_val) {
            	
            	selectedUsername =  new_val;
                System.out.println(selectedUsername);

            }
        });
        
        SignInController.stage1.show();

    }

    
    @FXML
    protected void handleSendMessageButton(ActionEvent e) {
    	
    	int messageLength = writeNewMessage.getText().getBytes().length;
    	System.out.println("MESSAGE NAME : " + imgFile.getName());
    	long imageSize = steganography.getImagesSize(imgFile.getName());
    	//for(int i = 0; i < imagesSize.length; i++) {
	    	if(messageLength < imageSize / 100 ) {
	    		//do logic for  adding message to picture
	    		//encodeText(imageToByte(image), );
	    		if(steganography.encode("src/images", "girl", "jpg", "girl_steg", writeNewMessage.getText())) {
	    			alert("You succesfuly encoded text!");
	    		}
	    	} else {
	    		alert("Your message is too large for selected image");
	    	}
    }
    
    @FXML
    protected void handleShowNewMessagesButton(ActionEvent e) {
    	newMessagesLabel.setVisible(false);
    	viewNewMessages.setVisible(true);
    	viewNewMessages.setText(steganography.decode("src/images", "girl_steg"));
    	
    }
    
    @FXML
    protected void browsePictureButtonHandler(ActionEvent e) {
    	if(!writeNewMessage.getText().isEmpty()) {
	    	FileChooser fileChooser = new FileChooser();
	    	configureFileChooser(fileChooser);
	    	imgFile = new File("src/images");
	    	if(imgFile .exists()) {
	    		fileChooser.setInitialDirectory(imgFile);
	    	}
	    	imgFile = fileChooser.showOpenDialog(SignInController.stage1);
//	    	try {
	    		System.out.println(imgFile.getName());
//				image = ImageIO.read(file);
//			} catch (IOException e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}

	    	//}
    	} else {
    		alert("Write message first!");
    	}
    }
    
    

	private static void configureFileChooser(final FileChooser fileChooser) {

        fileChooser.setTitle("Select image");
        fileChooser.setInitialDirectory(new File("../images"));
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("JPG", "*.jpg"));
    }


    


    protected static void alert(String message) {

        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }
    
 

}
