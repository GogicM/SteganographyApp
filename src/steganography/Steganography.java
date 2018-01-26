package steganography;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;

import controllers.UserPanelController;
import crypto.Crypto;
import message.Message;

public class Steganography {
	
   public byte[] encodeText(byte[] image, byte[] addition, int offset) {
	   
	   if(addition.length + offset > image.length) {
		   throw new IllegalArgumentException("File not long enough!");
	   }
	   for(int i=0; i < addition.length; ++i) {
		   int add = addition[i];
		   for(int bit=7; bit>=0; --bit, ++offset) {
			   int b = (add >>> bit) & 1;
    	   	   image[offset] = (byte)((image[offset] & 0xFE) | b );
		   }
	   }
	   return image;
    }
    
	public byte[] decodeText(byte[] image) {
		
		int length = 0;
		int offset  = 32;
		//loop through 32 bytes of data to determine text length
		System.out.println(image.toString());
		for(int i=0; i<32; ++i) { //i=24 will also work, as only the 4th byte contains real data
			length = (length << 1) | (image[i] & 1);
			System.out.println("LENGTH : " + length);

		}
		System.out.println("LENGTH : " + length);
		byte[] result = new byte[length];
		
		//loop through each byte of text
		for(int b=0; b<result.length; ++b ) {
			//loop through each bit within a byte of text
			for(int i=0; i<8; ++i, ++offset) {
				//assign bit: [(new byte value) << 1] OR [(text byte) AND 1]
				result[b] = (byte)((result[b] << 1) | (image[offset] & 1));
			}
		}
		return result;
	}
	
	public long getImagesSize(String imageName) {
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
	
	public byte[] imageToByte(BufferedImage image) {
	    	
		byte[] imageBytes;
	    	
	    	WritableRaster raster = image.getRaster();
	    	DataBufferByte buffer = (DataBufferByte) raster.getDataBuffer();
	    	imageBytes = buffer.getData();
	    	
	    	return imageBytes;
	    	
	    }
	
	public boolean encode(String path, String original, String ext1, String stegan, Message message, PublicKey publicKey) {
			
			Crypto crypto = null;
			try {
				crypto = new Crypto();
			} catch (Exception e1) {
				e1.printStackTrace();
			} 
			String file_name = createPathToImage(path,original,ext1);
			System.out.println(file_name);
			BufferedImage image_orig = getImage(file_name);
			image_orig = user_space(image_orig);
			//user space is not necessary for Encrypting
			//BufferedImage image = user_space(image_orig);
			String encryptedMessage = null;
			try {
				encryptedMessage = crypto.EncryptStringAsymmetric(message.getContent(), publicKey);
				System.out.println(encryptedMessage);

			} catch (Exception e) {
				e.printStackTrace();
			}
			image_orig = add_text(image_orig, encryptedMessage);
			
			return(setImage(image_orig,new File(createPathToImage(path, original,"png")),"png"));
	}
		
	public String decode(String path, String name, PrivateKey privateKey) {
			
		byte[] decode;
		try {
			Crypto crypto = new Crypto();
			//user space is necessary for decrypting
			BufferedImage image  = user_space(getImage(createPathToImage(path,name,"png")));
			decode = decodeText(imageToByte(image));
			String encText = new String(decode);
			String msg = crypto.DecryptStringAsymmetric(encText, privateKey);

			return(msg);
		} catch(Exception e) {
				e.printStackTrace();
				return "";
			}
	}
	
	public String createPathToImage(String path, String name, String ext) {
		return path + "/" + name + "." + ext;
	}
		
	private BufferedImage add_text(BufferedImage image, String text) {
		//convert all items to byte arrays: image, message, message length
		byte img[] = imageToByte(image);
		byte msg[] = text.getBytes();
		byte len[] = intToByteConversion(msg.length);
		try {
			encodeText(img, len,  0); //0 first positiong
			encodeText(img, msg, 32); //4 bytes of space for length: 4bytes*8bit = 32 bits
		} catch(Exception e) {
			e.printStackTrace();
		}
		return image;
	}
		
	public BufferedImage getImage(String f) {
		BufferedImage image	= null;
		File file = new File(f);
			
		try {
			image = ImageIO.read(file);
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		return image;
	}
		
	public BufferedImage user_space(BufferedImage image) {
			
		//create new_img with the attributes of image
		BufferedImage new_img  = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
		Graphics2D	graphics = new_img.createGraphics();
		graphics.drawRenderedImage(image, null);
		//graphics.dispose(); //release all allocated memory for this image
		return new_img;
	}
		
	public byte[] intToByteConversion(int i) {
		//originally integers (ints) cast into bytes
		//byte byte7 = (byte)((i & 0xFF00000000000000L) >>> 56);
		//byte byte6 = (byte)((i & 0x00FF000000000000L) >>> 48);
		//byte byte5 = (byte)((i & 0x0000FF0000000000L) >>> 40);
		//byte byte4 = (byte)((i & 0x000000FF00000000L) >>> 32);
			
		//only using 4 bytes
		byte byte3 = (byte)((i & 0xFF000000) >>> 24); //0
		byte byte2 = (byte)((i & 0x00FF0000) >>> 16); //0
		byte byte1 = (byte)((i & 0x0000FF00) >>> 8 ); //0
		byte byte0 = (byte)((i & 0x000000FF)	   );
		//{0,0,0,byte0} is equivalent, since all shifts >=8 will be 0
		return(new byte[]{byte3,byte2,byte1,byte0});
	}
		
		
		
	public boolean setImage(BufferedImage image, File file, String ext) {
		try {
			file.delete(); //delete resources used by the File
			ImageIO.write(image,ext,file);
			return true;
		} catch(Exception e) {
			return false;
		}
	}
}
