package controllers;

import java.awt.Desktop;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
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
    
    private final Desktop desktop = Desktop.getDesktop();

    private static final int PORT_NUMBER = 9999;
    private static String PATH = "src/server/users";
    
    protected static ObservableList<String> data = FXCollections.observableArrayList();

    @FXML
    ListView<String> list;
    @FXML
    private Button sendMessageButton;
    @FXML
    private Button downloadButton;
    @FXML
    private Button showLogsButton;
    @FXML
    private TextArea messageField;
    @FXML
    private TextArea logs;
    @FXML
    private TextArea newFileContent;
    @FXML
    private Button uploadNewButton;

    protected static String newFileData;

    @FXML
    private void initialize() {
    //    tArea.setVisible(false);
       // logs.setVisible(false);
//        try {
//            String[] fileNames = getFileNames();
//            data.addAll(fileNames);
//
//        } catch (ClassNotFoundException | IOException e1) {
//            e1.printStackTrace();
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        }
        list.setItems(data);
        userName = SignInController.uName;

        list.getSelectionModel().selectedItemProperty().addListener(
                new ChangeListener<String>() {
            public void changed(ObservableValue<? extends String> ov,
                    String old_val, String new_val) {
            	selectedUsername =  new_val;
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

    @FXML
    protected void handleUploadNewFile(ActionEvent event) {
        if (newFileContent.getText().isEmpty()) {
            alert("You can't upload empty file!");
        } else {
            FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/uploadNewFileForm.fxml"));
            try {
                newFileData = newFileContent.getText();
                Parent root = (Parent) loader.load();

                SendNewMessageController controller = loader.getController();

                Stage stage = new Stage();
                stage.setTitle(" User panel");
                stage.setScene(new Scene(root));
                stage.show();
//        stage.hide();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    @FXML
    protected void handleBrowseButton(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        configureFileChooser(fileChooser);
        File file = new File("src/certificates");
        if (file.exists()) {
            //bug in FileChooser, one must set initial directory or it will throw exception
            fileChooser.setInitialDirectory(file);
        }
        file = fileChooser.showOpenDialog(SignInController.stage1);
        if(true) { //mokup condition, when I complete it, it will check can message fit in image
        	alert("Message can not fit in selected image.");
        	sendMessageButton.setVisible(false);
        }
        if (messageField.getText() != null ) {
        	sendMessageButton.setVisible(true);
        }

    }
    @FXML
    protected void handleSendMessageButton(ActionEvent e) {
    	
    }
    private Window getStage() {
		// TODO Auto-generated method stub
		return null;
	}

	private static void configureFileChooser(final FileChooser fileChooser) {

        fileChooser.setTitle("Select your certificate");
        fileChooser.setInitialDirectory(new File("../certificates"));
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("CRT", "*.crt"));
    }

    private void openFile(File file) {
        try {
            desktop.open(file);
        } catch (IOException e) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, e);
        }
    }
    
    private String[] getFileNames() throws IOException, ClassNotFoundException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        String[] userNames;
        String[] cUserNames;
        String option = "users";
        String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric("users", SignInController.serverPublicKey);
        String signature = null;
        try {
            signature = SignInController.asymmetricCrypto.signMessagge(option, SignInController.privateKey);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        SignInController.oos.writeObject("");
        SignInController.oos.writeObject(new String[]{signature, encOption});

        cUserNames = (String[]) SignInController.ois.readObject();
        
        

        userNames = new String[cUserNames.length];
        try {
        	userNames = SignInController.asymmetricCrypto.DecryptStringArraySymmetric(userNames, SignInController.sessionKey);

        } catch (Exception e) {

            e.printStackTrace();
        }
        return userNames;
    }

    protected static void alert(String message) {

        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }

}
