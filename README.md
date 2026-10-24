CRYPTIQ
Description:
CRYPTIQ is a standalone, offline desktop security application built in Core Java that protects sensitive data from leaking into public AI tools (such as ChatGPT or GitHub Copilot). When developers paste code for debugging, CRYPTIQ automatically scans the text using multithreaded regular expressions (Regex) to detect confidential tokens—including API keys, private IPv4 addresses, database connection URLs, and email addresses. 
It replaces them with reversible placeholder tags (e.g., [REDACTED_API_KEY_1]), securely vaults the original secrets in an isolated, in-memory SQLite database, and provides one-click two-way restoration when the AI response is pasted back. It operates with zero internet access and leaves no plaintext disk footprint.

Prerequisites:
=>Java Development Kit (JDK 8 or above)
=>SQLite JDBC driver placed in the same folder: sqlite-jdbc-3.36.0.3.jar (or renamed to sqlite-jdbc.jar)

Commands:

=>Windows (Command Prompt / PowerShell)

Compile: javac -cp ".;sqlite-jdbc-3.36.0.3.jar" CryptiqApp.java

Run: java -cp ".;sqlite-jdbc-3.36.0.3.jar" CryptiqApp

=>macOS / Linux (Terminal)

Compile: javac -cp ".:sqlite-jdbc-3.36.0.3.jar" CryptiqApp.java

Run: java -cp ".:sqlite-jdbc-3.36.0.3.jar" CryptiqApp

=>Workflow

Scrub: Paste raw code into the left pane, select detection filters, and click Scrub Text.

Copy: Click Copy to Clipboard and paste the sanitized code into your AI assistant.

Restore: Paste the AI-generated code back into the right pane and click Restore Original.

Audit: Click View Audit Log to inspect timestamped logs and rule execution history.
