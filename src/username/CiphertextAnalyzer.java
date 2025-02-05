package username;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * A utility program to help analyze multiple ciphertexts encrypted with the same one-time pad.
 * This program provides various analysis tools through an interactive menu interface.
 *
 * Key features:
 * - Reads ciphertexts from a file in the data directory
 * - Allows XORing any two ciphertexts
 * - Shows binary patterns to help identify spaces
 * - Supports testing plaintext guesses against all ciphertexts
 *
 * File structure:
 * YourProject/
 *     ├── src/
 *     │   └── username/
 *     │       └── CiphertextAnalyzer.java
 *     └── data/
 *         └── ciphertexts_to_decrypt.txt
 */
public class CiphertextAnalyzer {
    // Store loaded ciphertexts
    private List<String> ciphertexts;

    // File path constants
    private static final String DATA_DIR = "data";
    private static final String CIPHERTEXT_FILE = "ciphertexts_to_decrypt.txt";

    // Scanner for user input
    private Scanner scanner;

    /**
     * Constructor initializes the ciphertexts list and scanner.
     */
    public CiphertextAnalyzer() {
        ciphertexts = new ArrayList<>();
        scanner = new Scanner(System.in);
    }

    /**
     * Loads ciphertexts from the data directory.
     * Expects one ciphertext per line in hexadecimal format.
     */
    private void loadCiphertexts() throws IOException {
        // Get current working directory (project root in IntelliJ)
        String currentDir = System.getProperty("user.dir");
        System.out.println("Current working directory: " + currentDir);

        // Construct and verify data directory path
        Path dataDir = Paths.get(currentDir, DATA_DIR);
        System.out.println("Looking for data directory at: " + dataDir.toAbsolutePath());

        if (!Files.exists(dataDir)) {
            throw new IOException(
                    "Data directory not found. Please create a 'data' folder in your project root directory: "
                            + dataDir.toAbsolutePath());
        }

        // Construct and verify input file path
        Path inputPath = dataDir.resolve(CIPHERTEXT_FILE);
        System.out.println("Looking for input file at: " + inputPath.toAbsolutePath());

        if (!Files.exists(inputPath)) {
            throw new IOException(
                    "Input file not found. Please place 'ciphertexts_to_decrypt.txt' in your data folder: "
                            + inputPath.toAbsolutePath());
        }

        // Read all lines from the file
        List<String> lines = Files.readAllLines(inputPath);
        if (lines.isEmpty()) {
            throw new IOException("File is empty: " + inputPath);
        }

        // Process each line
        for (String line : lines) {
            line = line.trim();  // Remove leading/trailing whitespace
            if (!line.isEmpty()) {
                if (isValidHex(line)) {
                    ciphertexts.add(line);
                } else {
                    System.out.println("Warning: Skipping invalid hex line: " + line);
                }
            }
        }

        // Verify we loaded valid ciphertexts
        if (ciphertexts.isEmpty()) {
            throw new IOException("No valid ciphertexts found in " + inputPath);
        }

        System.out.println("Successfully loaded " + ciphertexts.size() + " ciphertexts");
    }

    /**
     * Validates if a string contains only valid hexadecimal characters.
     */
    private boolean isValidHex(String hex) {
        return hex.matches("[0-9A-Fa-f]+");
    }

    /**
     * Performs XOR operation on two hexadecimal strings.
     */
    private String xorHex(String hex1, String hex2) {
        if (hex1.length() != hex2.length()) {
            throw new IllegalArgumentException("Hexadecimal strings must be of equal length");
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex1.length(); i += 2) {
            // Convert each pair of hex digits to integers and XOR them
            int value1 = Integer.parseInt(hex1.substring(i, i + 2), 16);
            int value2 = Integer.parseInt(hex2.substring(i, i + 2), 16);
            result.append(String.format("%02X", value1 ^ value2));
        }
        return result.toString();
    }

    /**
     * Displays the XOR result with helpful analysis information.
     */
    private void displayAnalysis(String xorResult) {
        System.out.println("\nAnalysis of XOR Result:");
        System.out.println("------------------------");
        System.out.println("Complete hex result: " + xorResult);

        System.out.println("\nDetailed byte-by-byte analysis:");
        System.out.printf("%-8s | %-6s | %-8s | %-20s%n",
                "Position", "Hex", "Binary", "Notes");
        System.out.println("-".repeat(50));

        for (int i = 0; i < xorResult.length(); i += 2) {
            int value = Integer.parseInt(xorResult.substring(i, i + 2), 16);
            String binary = String.format("%8s",
                    Integer.toBinaryString(value)).replace(' ', '0');

            // Add helpful notes about the pattern
            String notes = "";
            if (binary.startsWith("01")) {
                notes = "Possible space/letter pair";
            } else if (binary.startsWith("00")) {
                notes = "Same character type";
            }

            System.out.printf("%-8d | %02X     | %8s | %s%n",
                    i/2, value, binary, notes);
        }
    }

    /**
     * Shows the main menu and handles user interaction.
     */
    public void showMenu() {
        while (true) {
            System.out.println("\nCiphertext Analysis Menu");
            System.out.println("=======================");
            System.out.println("1. XOR two specific ciphertexts");
            System.out.println("2. XOR all ciphertexts with the first one");
            System.out.println("3. Display all loaded ciphertexts");
            System.out.println("4. Test a plaintext guess");
            System.out.println("5. Exit");

            System.out.print("\nEnter your choice (1-5): ");

            try {
                int choice = scanner.nextInt();
                scanner.nextLine(); // Clear the buffer

                switch (choice) {
                    case 1:
                        handleXORTwo();
                        break;
                    case 2:
                        handleXORAll();
                        break;
                    case 3:
                        displayAllCiphertexts();
                        break;
                    case 4:
                        handlePlaintextGuess();
                        break;
                    case 5:
                        System.out.println("Goodbye!");
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            } catch (InputMismatchException e) {
                System.out.println("Please enter a number between 1 and 5.");
                scanner.nextLine(); // Clear the invalid input
            }
        }
    }

    /**
     * Handles the XOR operation between two selected ciphertexts.
     */
    private void handleXORTwo() {
        displayAllCiphertexts();
        System.out.print("\nEnter number of first ciphertext (0-" +
                (ciphertexts.size()-1) + "): ");
        int first = scanner.nextInt();
        System.out.print("Enter number of second ciphertext: ");
        int second = scanner.nextInt();

        if (first >= 0 && first < ciphertexts.size() &&
                second >= 0 && second < ciphertexts.size()) {
            String xorResult = xorHex(ciphertexts.get(first),
                    ciphertexts.get(second));
            displayAnalysis(xorResult);
        } else {
            System.out.println("Invalid ciphertext numbers.");
        }
    }

    /**
     * XORs all ciphertexts with the first one and displays results.
     */
    private void handleXORAll() {
        if (ciphertexts.isEmpty()) {
            System.out.println("No ciphertexts loaded.");
            return;
        }

        String reference = ciphertexts.get(0);
        for (int i = 1; i < ciphertexts.size(); i++) {
            System.out.println("\nXORing ciphertext 0 with ciphertext " + i + ":");
            String xorResult = xorHex(reference, ciphertexts.get(i));
            displayAnalysis(xorResult);
        }
    }

    /**
     * Displays all loaded ciphertexts with their index numbers.
     */
    private void displayAllCiphertexts() {
        System.out.println("\nLoaded Ciphertexts:");
        for (int i = 0; i < ciphertexts.size(); i++) {
            System.out.printf("%d: %s%n", i, ciphertexts.get(i));
        }
    }

    /**
     * JUST FOR FUN: Tests a complete plaintext guess against all ciphertexts to help with cryptanalysis.
     *
     * In this lab, each ciphertext represents a 31-character English sentence that was
     * encrypted using the same key. To test your theories about what these messages might
     * be, you must provide a complete 31-character guess. This requirement exists because
     * the one-time pad encryption operates on fixed-length messages.
     *
     * How to Use This Method:
     * 1. Form a complete 31-character guess of what you think one of the messages might be
     * 2. Enter your guess when prompted
     * 3. The program will convert your guess to hex and XOR it with each ciphertext
     * 4. Study the results to see if your guess reveals patterns of English text
     *
     * When Your Guess is Correct:
     * If your guess matches one of the original messages:
     * - XORing it with that message's ciphertext will reveal the encryption key
     * - This same key, when XORed with other ciphertexts, will reveal their plaintexts
     * - You'll see readable English text appear in the results
     *
     * Length Requirement:
     * Your guess must be exactly 31 characters long. This includes:
     * - Letters (uppercase or lowercase)
     * - Spaces
     * - Punctuation
     * - Any other ASCII characters that might appear in an English sentence
     *
     * If you want to test a shorter phrase, you'll need to:
     * 1. Think about where in the message your phrase might appear
     * 2. Pad the rest of the guess with reasonable characters to reach 31 characters
     * 3. Enter the complete 31-character guess
     *
     * Example:
     * If you think a message starts with "The", you might enter:
     * "The                             " (padding with spaces to 31 chars)
     *
     * @throws IllegalArgumentException if the guess is not exactly 31 characters long
     */
    private void handlePlaintextGuess() {
        System.out.println("\nNote: Your guess must be exactly 31 characters long.");
        System.out.println("This includes letters, spaces, and punctuation.");
        System.out.println("If testing a shorter phrase, pad with spaces to reach 31 characters.\n");

        System.out.print("Enter your plaintext guess: ");
        String guess = scanner.nextLine();

        // Verify the length requirement before proceeding
        if (guess.length() != 31) {
            System.out.printf("Error: Your guess is %d characters long. It must be exactly 31 characters.%n",
                    guess.length());
            return;
        }

        // Convert plaintext guess to hex format
        StringBuilder hexGuess = new StringBuilder();
        for (char c : guess.toCharArray()) {
            hexGuess.append(String.format("%02X", (int)c));
        }

        System.out.println("\nTesting your guess against all ciphertexts...");

        // Test against each ciphertext
        for (int i = 0; i < ciphertexts.size(); i++) {
            try {
                String xorResult = xorHex(hexGuess.toString(), ciphertexts.get(i));
                System.out.println("\nResult for ciphertext " + i + ":");
                System.out.println("Complete hex result: " + xorResult);
            } catch (IllegalArgumentException e) {
                // This shouldn't happen due to length check above, but handle just in case
                System.out.println("Error: Unexpected length mismatch. Please report this bug.");
                break;
            }
        }
    }

    /**
     * Main program entry point.
     */
    public static void main(String[] args) {
        CiphertextAnalyzer analyzer = new CiphertextAnalyzer();
        try {
            analyzer.loadCiphertexts();
            analyzer.showMenu();
        } catch (IOException e) {
            System.err.println("Error loading ciphertexts: " + e.getMessage());
        }
    }
}