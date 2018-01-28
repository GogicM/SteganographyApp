package controllers;

import java.awt.Desktop;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
    private KeyGenerator keyGenerator;
    private SecretKey sessionKey;
    private String messageContent;

    private ArrayList<Message> messages = new ArrayList<>();
    
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
    	
    	messageContent = new String("");
    	steganography = new Steganography();
    	viewNewMessages.setVisible(false);
    	String[] uNames = new String[] { "user", "student"};
//    	for(String s : uNames) {
//    		if(s.equals(SignInController.uName)) {
//    			continue;
//    		}
    		data.add("user");
    		data.add("student");

   // 	}


    	try {
            list.getSelectionModel().selectedItemProperty().addListener(
                    new ChangeListener<String>() {
                public void changed(ObservableValue<? extends String> ov,
                        String old_val, String new_val) {
                	
                	selectedUsername =  new_val;
                    System.out.println(selectedUsername);

                }
            });
            list.setItems(data);
            userName = SignInController.uName;
    		crypto = new Crypto();
    		int newMessageNumber = 0;
    		File f1 = new File("src/" + SignInController.uName);
    		if(!f1.exists() || f1.length() == 0) {
    			newMessages = new ArrayList<>();
    		} else {
    			newMessages = deserializeMessages(SignInController.uName);
    			for(Message m : newMessages) {
        			if(!m.getIsRead()) {
        				newMessageNumber++;
        			}
        		}
    		}
    	
    		newMessagesLabel.setText("You have " + newMessageNumber + " message(s)");
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
        
        SignInController.stage1.show();
    }

    
    @FXML
    protected void handleSendMessageButton(ActionEvent e) {
    	
    	if(!checkCertificate("src/certificates/" + SignInController.uName + ".crt")) {
    		alert("Bad certificate! Exiting app");
    		System.exit(0);
    	}
    	try {
    	int messageLength = writeNewMessage.getText().getBytes().length;
    	System.out.println("MESSAGE NAME : " + imgFile.getName());
    	long imageSize = getImagesSize(imgFile.getName());
	    	if(messageLength < imageSize / 100 ) {
	    		String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
	    		String messageContent = "< " + timeStamp + "> < " + SignInController.uName + " > : <" + writeNewMessage.getText() + " > ";
	    		Message message = new Message();
	    		message.setContent(messageContent);
	    		message.setIsRead(false);
	    		message.setTargetedUser(selectedUsername);
	    		if(steganography.encode("src/images", imgFile.getName().split(Pattern.quote("."))[0], "png", imgFile.getName().split(Pattern.quote("."))[0], message, crypto.getPublicKey("src/keys/" + selectedUsername + "Public.der"))) {
	    			message.setImageName(imgFile.getName().split(Pattern.quote("."))[0]);
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
    	for(Message m : newMessages) {
    		System.out.println(m.getImageName() + "_steg");
    		if(!m.getIsRead()) {
    			try {
    				if(!new File("src/images/" + m.getImageName() + ".png").exists()) {
    					alert("Someone deleted image externaly!");
    				}
					messageContent  += steganography.decode("src/images", m.getImageName(), crypto.getPrivateKey("src/keys/" + SignInController.uName + "DER.key"))
							+ System.lineSeparator();
				
					System.out.println(messageContent);
					m.setIsRead(true);
    		
					cleanMessages(m.getTargetedUser());
    			} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e1) {
					e1.printStackTrace();
				}
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
     	long imageSize;
     	int i = 0;
     	
     	imageSize = f.length();

     	return imageSize;
     }
    
    public void serializeMessages(String uName, Message m) throws NoSuchAlgorithmException {
    	
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        sessionKey = keyGenerator.generateKey();
        PublicKey pKey;
        String encSessionKey = null;
        String sessionKeyToString = null;
		try {
			System.out.println("Session key : " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
			sessionKeyToString = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
			pKey = crypto.getPublicKey("src/keys/" + uName + "Public.der");
	        encSessionKey = crypto.EncryptStringAsymmetric(sessionKey.toString(), pKey);
	        if(uName == null) {
	        	uName = SignInController.uName;
	        }
		
	        System.out.println(sessionKeyToString.length());
	        messages.add(m);
	        File f = new File("src/" + uName);
    
	    	if(!f.exists()) {
	    		f.createNewFile();
	    	}
	        ByteArrayOutputStream bos = new ByteArrayOutputStream();
	        ObjectOutputStream oos = new ObjectOutputStream(bos);
	        oos.writeObject(messages);
	        byte[] listBytes = bos.toByteArray();

	    	crypto.writeToFile(f, listBytes,sessionKey, false);
	    	writeKeyToFile(new File("src/" + uName + "Key"), sessionKey);
	    	//messages.toArray().toString().getBytes();
	    	System.out.println("SIZE OF KEY : " + encSessionKey.length());
//
//    		FileOutputStream fos = new FileOutputStream(f);
//    		ObjectOutputStream oos = new ObjectOutputStream(fos);
//    		oos.writeObject(encSessionKey + messages);
    		oos.flush();
    		oos.close();
    //		fos.close();
    	} catch(Exception e) {
    		e.printStackTrace();
    	} 
    }
    public void cleanMessages(String uName) {
    	
 		try {
	        if(uName == null) {
	        	uName = SignInController.uName;
	        }
		
	        File f = new File("src/" + uName);
    
	    	
	    	if(f.exists()) {
	    		boolean b = f.createNewFile();
	    		System.out.println(b);
	    	} 
	    

	        PrintWriter printWriter = new PrintWriter (f);
	        printWriter.print("");
	        printWriter.close ();           
	        printWriter.close();
    		//fos.close();
    	} catch(Exception e) {
    		e.printStackTrace();
    	} 
    }

    public ArrayList deserializeMessages(String uName) {
    	
    	ArrayList<Message> messages = null;
    	System.out.println("USER NAME : " + uName);
    	File f = new File("src/" + uName);
    	try {
    		
	    	if(!f.exists()) {
	    		f.createNewFile();
	    	}
	    	File keyFile = new File("src/keys/" + uName +"DER.key");
	    	PrivateKey privKey = crypto.getPrivateKey(keyFile.getAbsolutePath());
	    	SecretKey sessionKey = readKeyFromFile(new File("src/" + uName + "Key"), privKey);
	    	byte[] messagesByte = crypto.readFromFile(f, sessionKey);
	    	ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(messagesByte));
	    	messages = (ArrayList<Message>) ois.readObject();
//	    	FileInputStream  fis = new FileInputStream (f);
//    	    ObjectInputStream ois = new ObjectInputStream(fis);
//
//    		byte[] messagesByte = ois.readByte();
//    		
//    		ByteArrayInputStream bis = new ByteArrayInputStream(messageByte);
//
//    		messages = (ArrayList) ois.readObject();
//    		ois.close();
//    		fis.close();
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
    	return messages;
    }
    
    private void writeKeyToFile(File file, SecretKey key) throws IOException,
    BadPaddingException, InvalidKeyException,
    IllegalBlockSizeException {
    	
    	PublicKey pKey = crypto.getPublicKeyFromCert(selectedUsername);
    	byte[] encSessionKey = crypto.AsymmetricFileEncription(key.getEncoded(), pKey);
    	FileOutputStream fos = new FileOutputStream(file);
    	fos.write(encSessionKey);
    	fos.flush();
    	fos.close();
    }
    
    private SecretKey readKeyFromFile(File keyFile, PrivateKey privateKey)
            throws FileNotFoundException, IOException, GeneralSecurityException {

        byte[] encSessionKey = new byte[(int) keyFile.length()];
        FileInputStream fis = new FileInputStream(keyFile);
        fis.read(encSessionKey);
        fis.close();
        byte[] sessionKey = crypto.AsymmetricFileDecription(encSessionKey, privateKey);
        SecretKey secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");

        return secretKey;
    }
    
  private boolean checkCertificate(String pathToCertificate) {
    	
    	boolean isGood = false;
        X509Certificate certificate;

        try {
            X509CRLEntry revokedCertificate = null;
            X509CRL crl = null;

            CertificateFactory cFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(pathToCertificate);
            certificate = (X509Certificate) cFactory.generateCertificate(fis);
            crl = (X509CRL) cFactory.generateCRL(new DataInputStream(new FileInputStream("src/server/crl.pem")));
            revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
            if(revokedCertificate !=null){
                alert("Certificate invalid! Exiting application");
                System.exit(0);
            }

			certificate.checkValidity();
			isGood = true;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    	return isGood;
    }
}
