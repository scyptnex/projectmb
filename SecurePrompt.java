import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/**
 * Example from Chapter 3
 * 
 * Simple object to prompt for user id/password.
 * 
 * @author Jeff Heaton
 * @version 1.0
 */

/**
 * This was written by Jeff heaton as Above
 * Modified by Nic Hollingum for CNS assignment 2
 * 
 * Can i just say this guy's coding style sucks
 */

public class SecurePrompt extends javax.swing.JDialog implements ActionListener{
	
	public static void main(String[] args){
		SecurePrompt d = new SecurePrompt(null);
		System.out.println(d.getLogin());
		System.out.println(d.getPassword());
	}

	JLabel JLabel1 = new javax.swing.JLabel();
	JLabel JLabel2 = new javax.swing.JLabel();
	JTextField _uid = new javax.swing.JTextField(20);
	JButton _ok = new javax.swing.JButton();
	JPasswordField _pwd = new javax.swing.JPasswordField(20);
	
	public SecurePrompt(Frame parent) {
		super(parent, true);
		setTitle("Login");
		
		Container con = getContentPane();
		con.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		
		JLabel1.setText("User ID:");
		JLabel2.setText("Password:");
		_ok.setText("OK");
		_ok.addActionListener(this);
		
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.EAST;
		con.add(JLabel1, gbc);
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.WEST;
		con.add(_uid, gbc);
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.anchor = GridBagConstraints.EAST;
		con.add(JLabel2, gbc);
		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.anchor = GridBagConstraints.WEST;
		con.add(_pwd, gbc);
		gbc.gridx = 0;
		gbc.gridy = 2;
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.gridwidth = 2;
		con.add(_ok, gbc);
		
		this.getRootPane().setDefaultButton(_ok);
		
		this.setContentPane(con);
		this.pack();
		
		this.setVisible(true);
	}
	
	public String getLogin(){
		return _uid.getText();
	}
	
	public char[] getPassword(){
		return _pwd.getPassword();
	}

	public void actionPerformed(java.awt.event.ActionEvent event) {
		this.dispose();
	}
}