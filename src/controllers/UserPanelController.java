package controllers;

import java.awt.Desktop;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.imageio.ImageIO;

import crypto.Crypto;
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
import message.Message;
import server.ServerThread;
import steganography.Steganography;

public class UserPanelController {


    private String fileName;
    private String userName;
    private String selectedUsername;
    private Steganography steganography;
    private File imgFile;
    private ArrayList<Message> newMessages;
    private Crypto crypto;
    private Message message = new Message();
    ArrayList<Message> messages = new ArrayList<>();
    
    protected static String newFileData;
    String messageContent;
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
    	
    	messageContent = new String("");
    	steganography = new Steganography();
    	viewNewMessages.setVisible(false);
    	try {
    		newMessages = (deserializeMessages(SignInController.uName).size() > 0) ? deserializeMessages(SignInController.uName) : new ArrayList<> ();
    		int newMessageNumber = 0;
    		for(Message m : newMessages) {
    			if(!m.getIsRead()) {
    				newMessageNumber++;
    			}
    		}
    		newMessagesLabel.setText("You have " + newMessageNumber + " message(s)");
    		crypto = new Crypto();
    		File f = new File("src/controllers/users.txt");
    		BufferedReader bReader = new BufferedReader(new FileReader(f));
    		String s = null;
    		while ((s = bReader.readLine()) != null) {
    			String uName = s.split("#")[0];
    			data.add(uName);
    		}
    		bReader.close();
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
        list.setItems(data);
        userName = SignInController.uName;

        list.getSelectionModel().selectedItemProperty().addListener(
                new ChangeListener<String>() {
            public void changed(ObservableValue<? extends String> ov,
                    String old_val, String new_val) {
            	
            	selectedUsername =  new_val;
                //System.out.println(selectedUsername);

            }
        });
        
        SignInController.stage1.show();
    }

    
    @FXML
    protected void handleSendMessageButton(ActionEvent e) {
    	try {
    	int messageLength = writeNewMessage.getText().getBytes().length;
    	System.out.println("MESSAGE NAME : " + imgFile.getName());
    	long imageSize = getImagesSize(imgFile.getName());
    	//for(int i = 0; i < imagesSize.length; i++) {
	    	if(messageLength < imageSize / 100 ) {
	    		//do logic for  adding message to picture
	    		//encodeText(imageToByte(image), );
	    		String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
	    		String messageContent = "< " + timeStamp + "> < " + SignInController.uName + " > : <" + writeNewMessage.getText() + " > ";
	    		Message message = new Message();
	    		message.setContent(messageContent);
	    		message.setIsRead(false);
	    		message.setTargetedUser(selectedUsername);
	    		if(steganography.encode("src/images", imgFile.getName().split(Pattern.quote("."))[0], "png", imgFile.getName().split(Pattern.quote("."))[0], message, crypto.getPublicKey("src/keys/" + selectedUsername + "Public.der"))) {
	    			//message = new Message(messageContent, false, selectedUsername);
	    			message.setImageName(imgFile.getName().split(Pattern.quote("."))[0]);
//	    			ArrayList<Message> newMessages = new ArrayList<>();
//	    			newMessages.add(message);
	    			serializeMessages(message.getTargetedUser(), message);
	    			alert("You succesfully encoded text!");
	    		}
	    	} else {
	    		alert("Your message is too large for selected image");
	    		//System.out.println(writeNewMessage.getText().getBytes().length);
	    	}
    	} catch(Exception ex) {
    		ex.printStackTrace();
    	}
    }
    
    @FXML
    protected void handleShowNewMessagesButton(ActionEvent e) {
    	
    	newMessagesLabel.setVisible(false);
    	viewNewMessages.setVisible(true);
    	
    	//System.out.println(newMessages.get(0).getContent());
    	
    	int i = 0;
    	System.out.println("SIZE OF NEW : " + newMessages.size());
    	for(Message m : newMessages) {
    		System.out.println(m.getImageName() + "_steg");
    		if(!m.getIsRead()) {
    			try {
					messageContent  += steganography.decode("src/images", m.getImageName(), crypto.getPrivateKey("src/keys/" + SignInController.uName + "DER.key"))
							+ System.lineSeparator();
				} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e1) {
					e1.printStackTrace();
				}
    			System.out.println(messageContent);
    			m.setIsRead(true);
    			serializeMessages(m.getTargetedUser(), m);
    			
    			i++;
    			//serializeMessages(m.getTargetedUser(), m);
    		}
    		viewNewMessages.setText(messageContent);
    		File f = new File("src/images/" + m.getImageName() + ".png");
			f.delete();
    		//messages = "";
    	}
    	//viewNewMessages.setText(steganography.decode("src/images", imgFile.getName().split(Pattern.quote("."))[0] + "_steg"));
    	
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
	    		//System.out.println(imgFile.getName().split(Pattern.quote("."))[0]);
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
                new FileChooser.ExtensionFilter("PNG", "*.png"));
    }


    


    protected static void alert(String message) {

        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }

    public long getImagesSize(String imageName) {
     	File f = new File("src/images/" + imageName);
     	//String[] fileNames = f.list();
     	long imageSize;
     	int i = 0;
     	
     	//for(String s : fileNames) {
     	//	File file = new File("src/images/" + s);
     		//System.out.println("FILE NAME : " + f.getName());
     		imageSize = f.length();
     		//System.out.println("IMAGE SIZE : " + imageSize);
     		//i++;
     	
     	return imageSize;
     }
    
    public void serializeMessages(String uName, Message m) {
    	
    	messages.add(m);
    	File f = new File("src/" + uName);
    	try {
	    	if(!f.exists()) {
	    		f.createNewFile();
	    	}
    	
    		FileOutputStream fos = new FileOutputStream(f);
    		ObjectOutputStream oos = new ObjectOutputStream(fos);
    		oos.writeObject(messages);
    		oos.flush();
    		oos.close();
    		fos.close();
    	} catch(IOException e) {
    		e.printStackTrace();
    	} 
    }
    
    public ArrayList deserializeMessages(String uName) {
    	
    	ArrayList<Message> messages = new ArrayList<> ();
    	
    	File f = new File("src/" + uName);
    	try {
	    	if(!f.exists()) {
	    		f.createNewFile();
	    	}
    	
	    	FileInputStream  fis = new FileInputStream (f);
    		ObjectInputStream ois = new ObjectInputStream(fis);
    		messages = (ArrayList) ois.readObject();
    		ois.close();
    		fis.close();
    	} catch(IOException | ClassNotFoundException e) {
    		e.printStackTrace();
    	}
    	return messages;
    }
}
