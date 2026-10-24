import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.*;

public class CryptiqApp extends Frame {

    private Checkbox chkApiKeys, chkEmails, chkIps, chkDbUrls;
    private TextArea inputArea, outputArea;
    private Button btnScrub, btnRestore, btnCopy, btnClear, btnViewAudit;
    private Label statusLabel;
    private Connection conn;

    public CryptiqApp() {
        super("CRYPTIQ — Desktop Secret Scrubber");
        initDatabase();
        initUI();
    }

    private void initDatabase() {
        try {
            // Explicitly load the SQLite JDBC driver class
            Class.forName("org.sqlite.JDBC");
            conn = DriverManager.getConnection("jdbc:sqlite::memory:");
            Statement stmt = conn.createStatement();

            // Table 1: secret_vault
            stmt.execute("CREATE TABLE IF NOT EXISTS secret_vault (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "tag TEXT NOT NULL UNIQUE, " +
                    "original_value TEXT NOT NULL, " +
                    "rule_type TEXT NOT NULL, " +
                    "created_at TEXT NOT NULL)");

            // Table 2: audit_log
            stmt.execute("CREATE TABLE IF NOT EXISTS audit_log (" +
                    "log_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "timestamp TEXT NOT NULL, " +
                    "rules_applied TEXT NOT NULL, " +
                    "redacted_count INTEGER NOT NULL, " +
                    "status TEXT NOT NULL)");

            stmt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initUI() {
        setLayout(new BorderLayout(8, 8));

        // 1. NORTH PANEL
        Panel northPanel = new Panel(new FlowLayout(FlowLayout.LEFT, 15, 8));
        chkApiKeys = new Checkbox("API Keys", true);
        chkEmails = new Checkbox("Emails", true);
        chkIps = new Checkbox("IP Addresses", true);
        chkDbUrls = new Checkbox("DB Connection URLs", true);

        northPanel.add(new Label("Active Rules:"));
        northPanel.add(chkApiKeys);
        northPanel.add(chkEmails);
        northPanel.add(chkIps);
        northPanel.add(chkDbUrls);
        add(northPanel, BorderLayout.NORTH);

        // 2. CENTER PANEL
        Panel centerPanel = new Panel(new GridLayout(1, 2, 10, 0));

        Panel leftBox = new Panel(new BorderLayout(4, 4));
        leftBox.add(new Label("Raw Source Code (Input):"), BorderLayout.NORTH);
        inputArea = new TextArea(15, 35);
        inputArea.setText("const key = \"sk_live_51Hxxxxxxxxxxxxxxxxx\";\n" +
                "db.connect(\"postgres://admin:pw@10.0.0.4:5432/prod\");\n" +
                "contact: dev.lead@company.com\n" +
                "server_ip = 192.168.1.42");
        leftBox.add(inputArea, BorderLayout.CENTER);

        Panel rightBox = new Panel(new BorderLayout(4, 4));
        rightBox.add(new Label("Masked Code (Output):"), BorderLayout.NORTH);
        outputArea = new TextArea(15, 35);
        outputArea.setEditable(false);
        rightBox.add(outputArea, BorderLayout.CENTER);

        centerPanel.add(leftBox);
        centerPanel.add(rightBox);
        add(centerPanel, BorderLayout.CENTER);

        // 3. SOUTH PANEL
        Panel southPanel = new Panel(new BorderLayout(6, 6));

        Panel buttonRow = new Panel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        btnScrub = new Button("Scrub Text");
        btnRestore = new Button("Restore Original");
        btnCopy = new Button("Copy Output");
        btnClear = new Button("Clear");
        btnViewAudit = new Button("View Audit Log");

        buttonRow.add(btnScrub);
        buttonRow.add(btnRestore);
        buttonRow.add(btnCopy);
        buttonRow.add(btnClear);
        buttonRow.add(btnViewAudit);

        statusLabel = new Label("Ready", Label.CENTER);
        statusLabel.setBackground(new Color(230, 235, 240));

        southPanel.add(buttonRow, BorderLayout.NORTH);
        southPanel.add(statusLabel, BorderLayout.SOUTH);
        add(southPanel, BorderLayout.SOUTH);

        btnScrub.addActionListener(e -> executeScrubbing());
        btnRestore.addActionListener(e -> executeRestoration());
        btnCopy.addActionListener(e -> copyOutputToClipboard());
        btnClear.addActionListener(e -> {
            inputArea.setText("");
            outputArea.setText("");
            updateStatus("Cleared input and output areas.");
        });
        btnViewAudit.addActionListener(e -> openAuditWindow());

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent we) {
                try {
                    if (conn != null && !conn.isClosed()) conn.close();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
                dispose();
                System.exit(0);
            }
        });

        setSize(850, 500);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void executeScrubbing() {
        updateStatus("Scrubbing in background...");

        new Thread(() -> {
            String text = inputArea.getText();
            if (text == null || text.trim().isEmpty()) {
                EventQueue.invokeLater(() -> updateStatus("Error: Input text is empty."));
                return;
            }

            int count = 0;
            String scrubbed = text;
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            java.util.List<String> rulesApplied = new ArrayList<>();

            try {
                if (chkApiKeys.getState()) {
                    rulesApplied.add("API_KEY");
                    Matcher m = Pattern.compile("sk_[a-zA-Z0-9_-]{16,}").matcher(scrubbed);
                    while (m.find()) {
                        String match = m.group();
                        String tag = "[REDACTED_API_KEY_" + (++count) + "]";
                        saveVaultRecord(tag, match, "API_KEY", timestamp);
                        scrubbed = scrubbed.replace(match, tag);
                    }
                }

                if (chkDbUrls.getState()) {
                    rulesApplied.add("DB_URL");
                    Matcher m = Pattern.compile("(postgres|mysql|mongodb):\\/\\/[^\\s\"']+").matcher(scrubbed);
                    while (m.find()) {
                        String match = m.group();
                        String tag = "[REDACTED_DB_URL_" + (++count) + "]";
                        saveVaultRecord(tag, match, "DB_URL", timestamp);
                        scrubbed = scrubbed.replace(match, tag);
                    }
                }

                if (chkEmails.getState()) {
                    rulesApplied.add("EMAIL");
                    Matcher m = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}").matcher(scrubbed);
                    while (m.find()) {
                        String match = m.group();
                        String tag = "[REDACTED_EMAIL_" + (++count) + "]";
                        saveVaultRecord(tag, match, "EMAIL", timestamp);
                        scrubbed = scrubbed.replace(match, tag);
                    }
                }

                if (chkIps.getState()) {
                    rulesApplied.add("IP");
                    Matcher m = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b").matcher(scrubbed);
                    while (m.find()) {
                        String match = m.group();
                        String tag = "[REDACTED_IP_" + (++count) + "]";
                        saveVaultRecord(tag, match, "IP", timestamp);
                        scrubbed = scrubbed.replace(match, tag);
                    }
                }

                saveAuditRecord(timestamp, String.join(", ", rulesApplied), count, "OK");

                final String resultText = scrubbed;
                final int totalFound = count;
                EventQueue.invokeLater(() -> {
                    outputArea.setText(resultText);
                    updateStatus("Finished. " + totalFound + " secret(s) redacted and vaulted.");
                });

            } catch (Exception ex) {
                saveAuditRecord(timestamp, String.join(", ", rulesApplied), 0, ex.getClass().getSimpleName());
                EventQueue.invokeLater(() -> updateStatus("Failed: " + ex.getMessage()));
            }
        }).start();
    }

    private void executeRestoration() {
        updateStatus("Restoring text from local vault...");

        new Thread(() -> {
            String text = outputArea.getText();
            if (text == null || text.trim().isEmpty()) {
                EventQueue.invokeLater(() -> updateStatus("Nothing to restore in output area."));
                return;
            }

            try {
                if (conn == null) {
                    EventQueue.invokeLater(() -> updateStatus("Database not initialized."));
                    return;
                }

                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT tag, original_value FROM secret_vault");

                String restored = text;
                int restoredCount = 0;
                while (rs.next()) {
                    String tag = rs.getString("tag");
                    String original = rs.getString("original_value");
                    if (restored.contains(tag)) {
                        restored = restored.replace(tag, original);
                        restoredCount++;
                    }
                }
                rs.close();
                stmt.close();

                final String finalText = restored;
                final int count = restoredCount;
                EventQueue.invokeLater(() -> {
                    outputArea.setText(finalText);
                    updateStatus("Restoration complete. " + count + " placeholder(s) replaced.");
                });

            } catch (SQLException ex) {
                EventQueue.invokeLater(() -> updateStatus("Restoration Error: " + ex.getMessage()));
            }
        }).start();
    }

    private void saveVaultRecord(String tag, String original, String type, String timestamp) throws SQLException {
        if (conn == null) return;
        String sql = "INSERT OR REPLACE INTO secret_vault (tag, original_value, rule_type, created_at) VALUES (?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, tag);
            ps.setString(2, original);
            ps.setString(3, type);
            ps.setString(4, timestamp);
            ps.executeUpdate();
        }
    }

    private void saveAuditRecord(String timestamp, String rules, int count, String status) {
        if (conn == null) return;
        String sql = "INSERT INTO audit_log (timestamp, rules_applied, redacted_count, status) VALUES (?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, timestamp);
            ps.setString(2, rules);
            ps.setInt(3, count);
            ps.setString(4, status);
            ps.executeUpdate();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    private void copyOutputToClipboard() {
        String text = outputArea.getText();
        if (!text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            updateStatus("Copied redacted output to clipboard.");
        }
    }

    private void updateStatus(String msg) {
        statusLabel.setText(msg);
    }

    private void openAuditWindow() {
        Dialog auditDialog = new Dialog(this, "Audit Log (SQLite)", true);
        auditDialog.setLayout(new BorderLayout(8, 8));

        TextArea logArea = new TextArea(12, 60);
        logArea.setEditable(false);

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-20s | %-25s | %-10s | %-10s\n", "TIMESTAMP", "RULES APPLIED", "REDACTED", "STATUS"));
        sb.append("-------------------------------------------------------------------------------\n");

        if (conn != null) {
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM audit_log ORDER BY log_id DESC")) {
                while (rs.next()) {
                    sb.append(String.format("%-20s | %-25s | %-10d | %-10s\n",
                            rs.getString("timestamp"),
                            rs.getString("rules_applied"),
                            rs.getInt("redacted_count"),
                            rs.getString("status")));
                }
            } catch (SQLException ex) {
                sb.append("Error loading logs: ").append(ex.getMessage());
            }
        } else {
            sb.append("Database connection is not available.");
        }

        logArea.setText(sb.toString());
        auditDialog.add(logArea, BorderLayout.CENTER);

        Button btnClose = new Button("Close");
        btnClose.addActionListener(e -> auditDialog.dispose());
        auditDialog.add(btnClose, BorderLayout.SOUTH);

        auditDialog.setSize(600, 300);
        auditDialog.setLocationRelativeTo(this);
        auditDialog.setVisible(true);
    }

    public static void main(String[] args) {
        new CryptiqApp();
    }
}