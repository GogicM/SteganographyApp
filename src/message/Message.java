package message;

import java.io.Serializable;

public class Message implements Serializable {
	
	private String content;
	private boolean isRead;
	
	public Message(String content, boolean isRead) {
		this.content = content;
		this.isRead = isRead;
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
}
