package message;

import java.io.Serializable;

public class Message implements Serializable {
	
	private String content;
	private String imageName;
	private String targetedUser;
	private boolean isRead;
	
	public Message(String content, boolean isRead, String targetedUser) {
		this.content = content;
		this.isRead = isRead;
		this.targetedUser = targetedUser;
	}
	
	public void setContent(String content) {
		this.content = content;
	}
	
	public String getContent() {
		return content;
	}
	
	public void setIsRead(boolean isRead) {
		this.isRead = isRead;
	}
	
	public boolean getIsRead() {
		return isRead;
	}
	
	public void setImageName(String imageName) {
		this.imageName = imageName;
	}
	
	public String getImageName() {
		return imageName;
	}
	
	public void setTargetedUser(String targetedUser) {
		this.targetedUser = targetedUser;
	}
	
	public String getTargetedUser() {
		return targetedUser;
	}
}
