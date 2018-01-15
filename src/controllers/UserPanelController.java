package controllers;

import java.awt.Desktop;
import java.awt.image.BufferedImage;
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

public class UserPanelController {


    private String fileName;
    private String userName;
    private String selectedUsername;
    private BufferedImage image = null;
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

//    @FXML
//    protected void handleSaveButton(ActionEvent event) {
//        if (!tArea.isVisible()) {
//            alert("You have to modify file in order to save it!");
//        } else {
//            try {
//                SignInController.oos.writeObject("");
//                String option = "modify";
//                String signature = SignInController.asymmetricCrypto.signMessagge(option, SignInController.privateKey);
//                String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric(option, SignInController.serverPublicKey);
//                SignInController.oos.writeObject(new String[]{signature, encOption});
//                String encData = SignInController.asymmetricCrypto.EncryptStringSymmetric(tArea.getText(), SignInController.sessionKey);
//                SignInController.oos.writeObject(new String[] {SignInController.asymmetricCrypto.signMessagge(tArea.getText(), SignInController.privateKey) ,encData});
//                String[] signatureAndStatus = (String[]) SignInController.ois.readObject();
//                String status = SignInController.asymmetricCrypto.DecryptStringSymmetric(signatureAndStatus[1], SignInController.sessionKey);
//                if(!SignInController.asymmetricCrypto.verifyDigitalSignature(status, signatureAndStatus[0], SignInController.serverPublicKey)) {
//                	alert("Intrusion occured! Exiting application...");
//                	System.exit(0);
//                }
//                if ("true".equals(status)) {
//                    alert("You successfully edited file");
//                } else {
//                    alert("File can not be edited");
//                }
//                tArea.setVisible(false);
//            } catch (Exception ex) {
//                Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
//            }
//        }
//
//    }

//    @FXML
//    protected void handleEditButton(ActionEvent event) {
//
//        tArea.setVisible(true);
//        String content = tArea.getText();
//        try {
//            SignInController.oos.writeObject("");
//            String option = "edit";
//            String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric(option, SignInController.serverPublicKey);
//            String signature = SignInController.asymmetricCrypto.signMessagge(option, SignInController.privateKey);
//            SignInController.oos.writeObject(new String[]{signature, encOption});
//            String encFileName = SignInController.asymmetricCrypto.EncryptStringSymmetric(fileName, SignInController.sessionKey);
//            SignInController.oos.writeObject(new String[] {SignInController.asymmetricCrypto.signMessagge(fileName, SignInController.privateKey), encFileName });
//            String[] signatureAndContent = (String[]) SignInController.ois.readObject();
//            String contentFromServer = SignInController.asymmetricCrypto.DecryptStringSymmetric(signatureAndContent[1], SignInController.sessionKey);
//            if(!SignInController.asymmetricCrypto.verifyDigitalSignature(contentFromServer, signatureAndContent[0], SignInController.serverPublicKey)) {
//            	alert("Intrusion occured! Exiting application...");
//            	System.exit(0);
//            }
//            tArea.setText(contentFromServer);
//        } catch (Exception ex) {
//            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
//        }
//
//    }

//    @FXML
//    protected void handleShowLogsButton(ActionEvent event) {
//        try {
//            String option = "logs";
//            String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric(option, SignInController.serverPublicKey);
//            String signature = SignInController.asymmetricCrypto.signMessagge(option, SignInController.privateKey);
//
//            SignInController.oos.writeObject("");
//            SignInController.oos.writeObject(new String[]{signature, encOption});
//            String[] logsAndSignatureFromServer = (String[]) SignInController.ois.readObject();
//            String logsFromServer = new String(SignInController.asymmetricCrypto.DecryptStringSymmetric(logsAndSignatureFromServer[1], SignInController.sessionKey));
//            if(!SignInController.asymmetricCrypto.verifyDigitalSignature(logsFromServer, logsAndSignatureFromServer[0], SignInController.serverPublicKey)) {
//            	alert("Intrusion has occured! Exiting application...");
//            	System.exit(0);
//            }
//            logs.setText(logsFromServer);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        logs.setVisible(true);
//    }

//    @FXML
//    protected void handleUploadNewFile(ActionEvent event) {
//        if (newFileContent.getText().isEmpty()) {
//            alert("You can't upload empty file!");
//        } else {
//            FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/uploadNewFileForm.fxml"));
//            try {
//                newFileData = newFileContent.getText();
//                Parent root = (Parent) loader.load();
//
//                SendNewMessageController controller = loader.getController();
//
//                Stage stage = new Stage();
//                stage.setTitle(" User panel");
//                stage.setScene(new Scene(root));
//                stage.show();
//        stage.hide();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//    }


//    @FXML
//    protected void handleBrowseButton(ActionEvent event) {
//        FileChooser fileChooser = new FileChooser();
//        configureFileChooser(fileChooser);
//        File file = new File("src/certificates");
//        if (file.exists()) {
//            //bug in FileChooser, one must set initial directory or it will throw exception
//            fileChooser.setInitialDirectory(file);
//        }
//        file = fileChooser.showOpenDialog(SignInController.stage1);
//        if(true) { //mokup condition, when I complete it, it will check can message fit in image
//        	alert("Message can not fit in selected image.");
//        	sendMessageButton.setVisible(false);
//        }
//        if (messageField.getText() != null ) {
//        	sendMessageButton.setVisible(true);
//        }
//    }
    
    @FXML
    protected void handleSendMessageButton(ActionEvent e) {
    	
    }
    
    @FXML
    protected void handleShowNewMessagesButton(ActionEvent e) {
    	newMessagesLabel.setVisible(false);
    	viewNewMessages.setVisible(false);
    }
    
    @FXML
    protected void browsePictureButtonHandler(ActionEvent e) {
    	if(!writeNewMessage.getText().isEmpty()) {
	    	FileChooser fileChooser = new FileChooser();
	    	configureFileChooser(fileChooser);
	    	File file = new File("src/images");
	    	if(file.exists()) {
	    		fileChooser.setInitialDirectory(file);
	    	}
	    	file = fileChooser.showOpenDialog(SignInController.stage1);
	    	try {
	    		System.out.println(file.getName());
				image = ImageIO.read(file);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
	    	int messageLength = writeNewMessage.getText().getBytes().length;
	    	System.out.println("MESSAGE SIZE : " + messageLength);
	    	long imageSize = getImagesSize(file.getName());
	    	//for(int i = 0; i < imagesSize.length; i++) {
		    	if(messageLength < imageSize / 100 ) {
		    		//do logic for  adding message to picture
		    		storeEncryptedMessageInPicture();
		    		
		    	} else {
		    		alert("Your message is too large for selected image");
		    	}
	    	//}
    	} else {
    		alert("Write message first!");
    	}
    }
    
    private void storeEncryptedMessageInPicture() {
		// TODO Auto-generated method stub
		
	}
    
    private byte[] encodeText(byte[] image, byte[] addition, int offset)
    {
    	if(addition.length + offset > image.length)
    	{
    		throw new IllegalArgumentException("File not long enough!");
    	}
    	for(int i=0; i<addition.length; ++i)
     	{
    		int add = addition[i];
    		for(int bit=7; bit>=0; --bit, ++offset)
    		{
    	   	 	int b = (add >>> bit) & 1;
    	   		 image[offset] = (byte)((image[offset] & 0xFE) | b );
    		}
    	}
    	return image;
    }
    
	private byte[] decodeText(byte[] image)
	{
		int length = 0;
		int offset  = 32;
		//loop through 32 bytes of data to determine text length
		for(int i=0; i<32; ++i) //i=24 will also work, as only the 4th byte contains real data
		{
			length = (length << 1) | (image[i] & 1);
		}
		
		byte[] result = new byte[length];
		
		//loop through each byte of text
		for(int b=0; b<result.length; ++b )
		{
			//loop through each bit within a byte of text
			for(int i=0; i<8; ++i, ++offset)
			{
				//assign bit: [(new byte value) << 1] OR [(text byte) AND 1]
				result[b] = (byte)((result[b] << 1) | (image[offset] & 1));
			}
		}
		return result;
	}
	
	private long getImagesSize(String imageName) {
    	File f = new File("src/images/" + imageName);
    	//String[] fileNames = f.list();
    	long imageSize;
    	int i = 0;
    	
    	//for(String s : fileNames) {
    	//	File file = new File("src/images/" + s);
    		System.out.println("FILE NAME : " + f.getName());
    		imageSize = f.length();
    		System.out.println("IMAGE SIZE : " + imageSize);
    		//i++;
    	
    	return imageSize;
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
