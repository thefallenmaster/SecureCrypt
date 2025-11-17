import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecureCrypt extends JFrame {

    private JTextArea inputArea, outputArea;
    private JComboBox<String> algoBox;
    private JButton encryptBtn, decryptBtn;
    private JPasswordField passwordField;
    private JCheckBox showPasswordCheckBox;
    private static final String AES_KEY = "1234567890123456";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    public SecureCrypt() {
        setTitle("🔐 Encryption / Decryption Tool");
        setSize(700, 550);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel background = new JPanel() {
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                GradientPaint gp = new GradientPaint(0, 0, new Color(135, 206, 250), 0, getHeight(), new Color(70, 130, 180));
                g2d.setPaint(gp);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        background.setLayout(new BorderLayout());
        setContentPane(background);

        inputArea = new JTextArea(5, 40);
        outputArea = new JTextArea(5, 40);
        outputArea.setEditable(false);

        JScrollPane inputScroll = new JScrollPane(inputArea);
        JScrollPane outputScroll = new JScrollPane(outputArea);
        inputScroll.setBorder(BorderFactory.createTitledBorder("📥 Input Text"));
        outputScroll.setBorder(BorderFactory.createTitledBorder("📤 Output Text"));

        String[] algos = {
                "Caesar Cipher", "Base64", "AES", "Reverse Text", "ROT13",
                "XOR Cipher", "Atbash Cipher", "Vigenere Cipher", "Hex Encode", "Substitution Cipher"
        };
        algoBox = new JComboBox<>(algos);

        passwordField = new JPasswordField(15);
        showPasswordCheckBox = new JCheckBox("Show Password");

        JPanel passPanel = new JPanel();
        passPanel.setOpaque(false);
        passPanel.add(new JLabel("🔑 Master Password (optional): "));
        passPanel.add(passwordField);
        passPanel.add(showPasswordCheckBox);

        encryptBtn = new JButton("🔒 Encrypt");
        decryptBtn = new JButton("🔓 Decrypt");

        JPanel topPanel = new JPanel(new GridLayout(2,1));
        topPanel.setOpaque(false);

        JPanel algoPanel = new JPanel();
        algoPanel.setOpaque(false);
        algoPanel.add(new JLabel("🎯 Algorithm: "));
        algoPanel.add(algoBox);

        topPanel.add(algoPanel);
        topPanel.add(passPanel);

        JPanel btnPanel = new JPanel();
        btnPanel.setOpaque(false);
        btnPanel.add(encryptBtn);
        btnPanel.add(decryptBtn);

        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 10, 10));
        centerPanel.setOpaque(false);
        centerPanel.add(inputScroll);
        centerPanel.add(outputScroll);

        background.add(topPanel, BorderLayout.NORTH);
        background.add(centerPanel, BorderLayout.CENTER);
        background.add(btnPanel, BorderLayout.SOUTH);

        setupMenuBar();
        setupEventListeners();
    }

    private void setupMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("📁 File");
        JMenuItem saveItem = new JMenuItem("💾 Save");
        JMenuItem loadItem = new JMenuItem("📂 Load");
        fileMenu.add(saveItem);
        fileMenu.add(loadItem);
        menuBar.add(fileMenu);

        // Add Help menu with About
        JMenu helpMenu = new JMenu("❓ Help");
        JMenuItem aboutItem = new JMenuItem("ℹ️ About");
        helpMenu.add(aboutItem);
        menuBar.add(helpMenu);

        setJMenuBar(menuBar);

        // Menu actions
        saveItem.addActionListener(e -> saveToFile());
        loadItem.addActionListener(e -> loadFromFile());
        aboutItem.addActionListener(e -> showAboutDialog());
    }

    private void setupEventListeners() {
        // Show password checkbox listener
        showPasswordCheckBox.addActionListener(e -> {
            if (showPasswordCheckBox.isSelected()) {
                passwordField.setEchoChar((char) 0); // Show password
            } else {
                passwordField.setEchoChar('•'); // Hide password
            }
        });

        encryptBtn.addActionListener(e -> {
            String input = inputArea.getText();
            String algo = (String) algoBox.getSelectedItem();
            try {
                String result = encrypt(input, algo);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
            }
        });

        decryptBtn.addActionListener(e -> {
            String input = inputArea.getText();
            String algo = (String) algoBox.getSelectedItem();
            try {
                String result = decrypt(input, algo);
                outputArea.setText(result);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
            }
        });
    }

    private void saveToFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write("Input:\n" + inputArea.getText() + "\n\n");
                writer.write("Output:\n" + outputArea.getText() + "\n");
                JOptionPane.showMessageDialog(this, "File saved successfully!");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + ex.getMessage());
            }
        }
    }

    private void loadFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
                inputArea.setText(content.toString().trim());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Error loading file: " + ex.getMessage());
            }
        }
    }

    private void showAboutDialog() {
        // Create a centered about dialog
        JPanel aboutPanel = new JPanel();
        aboutPanel.setLayout(new BoxLayout(aboutPanel, BoxLayout.Y_AXIS));
        aboutPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Title
        JLabel titleLabel = new JLabel("SecureCrypt");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Version
        JLabel versionLabel = new JLabel("Version 1.0");
        versionLabel.setFont(new Font("Arial", Font.BOLD, 14));
        versionLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Description
        JLabel descLabel = new JLabel("A powerful encryption/decryption tool");
        descLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        descLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Algorithms label
        JLabel algoLabel = new JLabel("Supported Algorithms:");
        algoLabel.setFont(new Font("Arial", Font.BOLD, 12));
        algoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Algorithms list
        JTextArea algoArea = new JTextArea();
        algoArea.setText("• Caesar Cipher\n• Base64\n• AES\n• Reverse Text\n• ROT13\n• XOR Cipher\n• Atbash Cipher\n• Vigenere Cipher\n• Hex Encode\n• Substitution Cipher");
        algoArea.setFont(new Font("Arial", Font.PLAIN, 11));
        algoArea.setBackground(aboutPanel.getBackground());
        algoArea.setEditable(false);
        algoArea.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Copyright
        JLabel copyrightLabel = new JLabel("© 2025 All rights reserved");
        copyrightLabel.setFont(new Font("Arial", Font.ITALIC, 10));
        copyrightLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Add components with spacing
        aboutPanel.add(titleLabel);
        aboutPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        aboutPanel.add(versionLabel);
        aboutPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        aboutPanel.add(descLabel);
        aboutPanel.add(Box.createRigidArea(new Dimension(0, 15)));
        aboutPanel.add(algoLabel);
        aboutPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        aboutPanel.add(algoArea);
        aboutPanel.add(Box.createRigidArea(new Dimension(0, 15)));
        aboutPanel.add(copyrightLabel);

        JOptionPane.showMessageDialog(this, aboutPanel, "ℹ️ About", JOptionPane.INFORMATION_MESSAGE);
    }

    // FIXED: Encryption methods now work without password
    private String encrypt(String text, String algo) throws Exception {
        // Apply algorithm first, then master password if provided
        String encryptedText = applyAlgorithm(text, algo, true);
        return applyMasterPassword(encryptedText, true);
    }

    private String decrypt(String text, String algo) throws Exception {
        // Remove master password first if provided, then apply algorithm
        String withoutMaster = applyMasterPassword(text, false);
        return applyAlgorithm(withoutMaster, algo, false);
    }

    private String applyAlgorithm(String text, String algo, boolean encrypt) throws Exception {
        switch (algo) {
            case "Caesar Cipher":
                return encrypt ? caesarCipher(text, 3) : caesarCipher(text, -3);
            case "Base64":
                return encrypt ? Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8))
                        : new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
            case "AES":
                return encrypt ? aesEncrypt(text) : aesDecrypt(text);
            case "Reverse Text":
                return new StringBuilder(text).reverse().toString();
            case "ROT13":
                return rot13(text);
            case "XOR Cipher":
                return xorCipher(text, "SECRETKEY");
            case "Atbash Cipher":
                return atbash(text);
            case "Vigenere Cipher":
                return encrypt ? vigenereEncrypt(text, "KEY") : vigenereDecrypt(text, "KEY");
            case "Hex Encode":
                return encrypt ? hexEncode(text) : hexDecode(text);
            case "Substitution Cipher":
                return encrypt ? substitutionEncrypt(text) : substitutionDecrypt(text);
            default:
                return text;
        }
    }

    private String applyMasterPassword(String text, boolean encrypting) throws Exception {
        String pwd = new String(passwordField.getPassword());
        if (pwd.isEmpty()) return text;
        return aesWithPassword(text, pwd, encrypting);
    }

    private String aesWithPassword(String text, String password, boolean encrypt) throws Exception {
        SecretKeySpec key = getAESKeyFromPassword(password);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        if (encrypt) {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } else {
            byte[] combined = Base64.getDecoder().decode(text);
            if (combined.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted data");
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        }
    }

    private SecretKeySpec getAESKeyFromPassword(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(key, "AES");
    }

    private String aesEncrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    private String aesDecrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");

        byte[] combined = Base64.getDecoder().decode(text);
        if (combined.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }

    private String caesarCipher(String text, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                c = (char) ((c - base + shift + 26) % 26 + base);
            }
            result.append(c);
        }
        return result.toString();
    }

    private String rot13(String text) {
        return caesarCipher(text, 13);
    }

    private String xorCipher(String text, String key) {
        StringBuilder result = new StringBuilder();
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char keyChar = (char) keyBytes[i % keyBytes.length];
            result.append((char) (c ^ keyChar));
        }

        String rawResult = result.toString();
        return Base64.getEncoder().encodeToString(rawResult.getBytes(StandardCharsets.UTF_8));
    }

    private String atbash(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append((char) ('Z' - (c - 'A')));
            } else if (Character.isLowerCase(c)) {
                result.append((char) ('z' - (c - 'a')));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String vigenereEncrypt(String text, String key) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int j = 0;
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                result.append((char) ((c - base + (key.charAt(j % key.length()) - 'A')) % 26 + base));
                j++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String vigenereDecrypt(String text, String key) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int j = 0;
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                result.append((char) ((c - base - (key.charAt(j % key.length()) - 'A') + 26) % 26 + base));
                j++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String hexEncode(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            result.append(String.format("%02x", (int) c));
        }
        return result.toString();
    }

    private String hexDecode(String hex) {
        hex = hex.replaceAll("[^0-9a-fA-F]", "");

        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length");
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String hexPair = hex.substring(i, i + 2);
            result.append((char) Integer.parseInt(hexPair, 16));
        }
        return result.toString();
    }

    private String substitutionEncrypt(String text) {
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        String subs  = "QWERTYUIOPASDFGHJKLZXCVBNMmnbvcxzlkjhgfdsapoiuytrewq";
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            int idx = plain.indexOf(c);
            result.append(idx >= 0 ? subs.charAt(idx) : c);
        }
        return result.toString();
    }

    private String substitutionDecrypt(String text) {
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        String subs  = "QWERTYUIOPASDFGHJKLZXCVBNMmnbvcxzlkjhgfdsapoiuytrewq";
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            int idx = subs.indexOf(c);
            result.append(idx >= 0 ? plain.charAt(idx) : c);
        }
        return result.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureCrypt().setVisible(true));
    }
}