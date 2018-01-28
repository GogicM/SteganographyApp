/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controllers;

import java.net.InetAddress;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import java.security.PrivateKey;
import crypto.Crypto;
import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.beans.property.StringProperty;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import server.ServerThread;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.codec.digest.DigestUtils;

/**
 *
 * @author Milan
 */
public class SignInController {

    public static Stage stage1 = new Stage();
    private Stage stage = new Stage();
    protected static ObjectOutputStream oos;
    protected static ObjectInputStream ois;
    protected static Crypto asymmetricCrypto;
    protected static SecretKey sessionKey;
    private static X509Certificate certificate;
    private PublicKey publicKey;
    private Crypto crypto;
    protected static PrivateKey privateKey;
    protected static PublicKey serverPublicKey;
    private final Desktop desktop = Desktop.getDesktop();
    public static String uName;
    private String password;
    @FXML
    private Button signIn;
    @FXML
    private TextField uNameTextField;
    @FXML
    private PasswordField pTextField;
    @FXML
    private Button browse;
    @FXML
    private Button send;
    @FXML
    private Label browseLabel;
    @FXML
    private Label addCertLabel;

    @FXML
    private void initialize() {
    	
        try {
			crypto = new Crypto();
		} catch (Exception e) {
			e.printStackTrace();
		} 
//		try {
//			keyGenerator = KeyGenerator.getInstance("AES");
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		if(!new File("src/users").exists()) {
			encryptUserCredentialsFile();
		}
    }

    @FXML
    protected void handleSignInButton(ActionEvent event) {

        if (!uNameTextField.getText().isEmpty() && !pTextField.getText().isEmpty()) {
            uName = uNameTextField.getText();
            password = pTextField.getText();

            try {
                if (new File("src\\keys\\" + uName + "Public.der").exists()) {
                    boolean login;
                    boolean flag = true;
                    System.out.println( "USER NAME  : " + uName + " PASSWORD : " + password);
                    String sha256HexPassword = cipher(password);
                    do {
                        login = loginCheck(uName, sha256HexPassword);
                    } while (!login);
                    if(checkCertificate("src/certificates/" + uName + ".crt")) {
	                    FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/userPanel.fxml"));
	                    Parent root = (Parent) loader.load();
	
	                    UserPanelController controller = loader.getController();
	
	                    stage1.setTitle(" User panel");
	                    stage1.setScene(new Scene(root));
	                    stage1.show();
	
	                    stage.hide();
                    } else {
                    	alert("Certificate has expired!");
                    	System.exit(0);
                    }

                } else {
                    alert("Username doesn't exist!");
                }
//            	oos.flush();
//            	oos.close();
//            	ois.close();
//            	socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            alert("Username or password field can not be empty!");
        }

    }

     public void setStage(Stage stage) {
        this.stage = stage;
    }

    private boolean loginCheck(String userName, String password)  {

    	boolean login = false;
        String line = null;
        
        try {
            File f = new File("src/users");
            if(!f.exists()) {
            	f.createNewFile();
            }
            FileInputStream fis = new FileInputStream(f);
            byte[] usersData = new byte[(int) f.length()];
            byte[] signature = new byte[684];
            byte[] key = new byte[512];
            byte[] data = new byte[224];
            
            fis.read(usersData);
            System.out.println(usersData[684]);
            for(int i = 0; i < 684; i ++) {
            	signature[i] = usersData[i];

            }
            for(int i = 684; i < 1196; i++) {
            	key[i - 684] = usersData[i];
            }
            for(int i = 1196; i < 1420; i++) {
            	data[i - 1196] = usersData[i];
            }
            byte[] decData = null;
            boolean sign = crypto.verifyDigitalSignature(new String(data), new String(signature), crypto.getPublicKey("src/ca/publicCA.key"));
            System.out.println(sign);
            //if(sign) {
            System.out.println("USLO");
            byte[] decKey = crypto.AsymmetricFileDecription(key, crypto.getPrivateKey("src/ca/privateCA.key"));
            SecretKey sKey = new SecretKeySpec(decKey, 0, decKey.length, "AES" );
            decData = crypto.SymmetricFileDecription(data, sKey);
            File f1 = new File("src/test.txt");
            f1.createNewFile();
            String msg = new String(decData);
            // }
            int i = 0;
            BufferedReader br = new BufferedReader(new FileReader(f));
            while (i < 3) {
            	String[] dataFromFile = msg.split(";");
            	System.out.println(dataFromFile[i]);
                String[] uNameAndPass = dataFromFile[i].split("#");
                String uName = uNameAndPass[0];
                String pass = uNameAndPass[1];
               
//            	System.out.println(userName + "#" + password);
//            	System.out.println(uName + "#" + pass);
//            	System.out.println(userName.length() + "#" + password.length());
//            	System.out.println(uName.length() + " " + pass.length());

                if ((userName).equals(uName) && (password).equals(pass)) {

                    login = true;

                    break;
                }
                i++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return login;
        //System.out.println("LOGIN : " + login);
        //return true;
    }


    protected static void alert(String message) {

        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error occured");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }

    //sha256 + salt for password storing on server
    private String getSHA256SecurePassword(String password, byte[] salt) {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    //method for generating salt
    private byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private String cipher(String password) {
        return DigestUtils.sha256Hex(password);
    }

    protected PrivateKey getPrivateKey() {
        return privateKey;
    }
    /*
     * Method that takes two byte arrays and concatenate them into one, appending one to another
     * 
     */
    private byte[] concatanateByteArrays(byte[] first, byte[] second) {
    	
    	//byte[] concatanated = new byte[(int) first.length + (int) second.length];
    	ByteArrayOutputStream output = new ByteArrayOutputStream();

    	try {
			output.write(first);
	    	output.write(second);

		} catch (IOException e) {
			e.printStackTrace();
		}
    	byte[] concatanated = output.toByteArray();

    	return concatanated;
    }
    
    /*
     * Helper method that checks certificate existence, validity , and crl list for user certificate
     * 
     */
    private boolean checkCertificate(String pathToCertificate) {
    	
    	boolean isGood = false;
    	
        try {
            X509CRLEntry revokedCertificate = null;
            X509CRL crl = null;

            CertificateFactory cFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(pathToCertificate);
            certificate = (X509Certificate) cFactory.generateCertificate(fis);
            publicKey = certificate.getPublicKey();
            crl = (X509CRL) cFactory.generateCRL(new DataInputStream(new FileInputStream("src/crl/crl.pem")));
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
    
    private void encryptUserCredentialsFile() {
    	try {
			
			File f = new File("src/users");
	        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	        keyGenerator.init(128);
	        SecretKey sessionKey = keyGenerator.generateKey();
	        privateKey = crypto.getPrivateKey("src/ca/privateCA.key");
            byte[] encData = crypto.SymmetricFileEncryption(Files.readAllBytes(Paths.get("src/controllers/users.txt")), sessionKey);
            String signature = crypto.signMessagge(Base64.getEncoder().encodeToString(encData), privateKey);
            byte[] encKey = crypto.AsymmetricFileEncription(sessionKey.getEncoded(), crypto.getPublicKey("src/ca/publicCA.key"));
//            System.out.println("KEY SIZE : " + encKey.length + " signature size : " + signature.getBytes().length
//            		+ " DATA : " + encData.length);
            System.out.println(signature);
            System.out.println("Data : " + new String(encData));
            System.out.println("ENC KEY : " + new String(encKey));

            byte[] keyAndData = crypto.concatanateByteArrays(encKey, encData);
         //   System.out.println(keyAndData.length);
            byte[] signedKeyAndData = crypto.concatanateByteArrays(signature.getBytes(), keyAndData);
        //    System.out.println(signedKeyAndData.length);
            FileOutputStream fos = new FileOutputStream(new File("src/users"));
            fos.write(signedKeyAndData);
    	} catch (Exception e) {
			e.printStackTrace();
		} 
    }
}
