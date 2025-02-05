package username;


import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * A utility program to help analyze multiple ciphertexts encrypted with the same one-time pad.
 * This program implements the XORed plaintext analysis approach, where we:
 * 1. First XOR pairs of ciphertexts to eliminate the encryption key
 * 2. Try guesses against these XORed plaintexts
 * 3. Look for readable English text that reveals successful matches
 */
public class CiphertextPairXOR {
    private List<String> ciphertexts;
    private static final String DATA_DIR = "data";
    private static final String CIPHERTEXT_FILE = "ciphertexts_to_decrypt.txt";
    private Scanner scanner;

    public CiphertextPairXOR() {
        ciphertexts = new ArrayList<>();
        scanner = new Scanner(System.in);
    }

    /**
     * Loads ciphertexts from the data directory.
     */
    private void loadCiphertexts() throws IOException {
        String currentDir = System.getProperty("user.dir");
        Path dataDir = Paths.get(currentDir, DATA_DIR);
        System.out.println("Looking for data directory at: " + dataDir.toAbsolutePath());

        if (!Files.exists(dataDir)) {
            throw new IOException("Data directory not found: " + dataDir.toAbsolutePath());
        }

        Path inputPath = dataDir.resolve(CIPHERTEXT_FILE);
        System.out.println("Looking for input file at: " + inputPath.toAbsolutePath());

        if (!Files.exists(inputPath)) {
            throw new IOException("Input file not found: " + inputPath.toAbsolutePath());
        }

        List<String> lines = Files.readAllLines(inputPath);
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                if (isValidHex(line)) {
                    ciphertexts.add(line);
                } else {
                    System.out.println("Warning: Skipping invalid hex line: " + line);
                }
            }
        }

        if (ciphertexts.size() < 2) {
            throw new IOException("Need at least 2 ciphertexts for analysis");
        }

        System.out.println("Successfully loaded " + ciphertexts.size() + " ciphertexts");
    }

    private boolean isValidHex(String hex) {
        return hex.matches("[0-9A-Fa-f]+");
    }

    /**
     * Performs XOR operation on two hexadecimal strings.
     * When used on two ciphertexts, this eliminates the encryption key,
     * leaving us with just the XOR of the two plaintexts.
     */
    private String xorHex(String hex1, String hex2) {
        if (hex1.length() != hex2.length()) {
            throw new IllegalArgumentException("Hexadecimal strings must be of equal length");
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hex1.length(); i += 2) {
            int value1 = Integer.parseInt(hex1.substring(i, i + 2), 16);
            int value2 = Integer.parseInt(hex2.substring(i, i + 2), 16);
            result.append(String.format("%02X", value1 ^ value2));
        }
        return result.toString();
    }

    /**
     * Creates all possible pairs of ciphertexts and returns their XOR results.
     * This is the key to our analysis - by XORing ciphertexts, we eliminate
     * the encryption key and work directly with relationships between plaintexts.
     */
    private List<XORPair> createCiphertextPairs() {
        List<XORPair> pairs = new ArrayList<>();
        for (int i = 0; i < ciphertexts.size(); i++) {
            for (int j = i + 1; j < ciphertexts.size(); j++) {
                String xorResult = xorHex(ciphertexts.get(i), ciphertexts.get(j));
                pairs.add(new XORPair(i, j, xorResult));
            }
        }
        return pairs;
    }

    /**
     * Tests a plaintext guess against XORed ciphertext pairs.
     * If our guess matches part of either plaintext, we'll see readable
     * English text appear in the corresponding positions of the result.
     */
    private void analyzeGuess(String guess, List<XORPair> pairs) {
        // Convert guess to hex
        StringBuilder hexGuess = new StringBuilder();
        for (char c : guess.toCharArray()) {
            hexGuess.append(String.format("%02X", (int)c));
        }
        String guessHex = hexGuess.toString();

        System.out.println("\nAnalyzing guess: \"" + guess + "\"");
        System.out.println("Testing against all ciphertext pairs...\n");

        // Try the guess at each position in each XORed pair
        for (XORPair pair : pairs) {
            System.out.printf("Results for ciphertexts %d and %d:%n", pair.index1, pair.index2);
            tryGuessAtPositions(guessHex, pair);
            System.out.println();
        }
    }

    /**
     * Tries a guess at all possible positions in an XORed pair.
     * This helps us find where in the messages our guessed text might appear.
     */
    private void tryGuessAtPositions(String guessHex, XORPair pair) {
        int maxStart = pair.xorResult.length() - guessHex.length();
        for (int start = 0; start <= maxStart; start += 2) {
            // Extract the portion of the XORed result we'll test against
            String portion = pair.xorResult.substring(start, start + guessHex.length());

            // XOR our guess with this portion
            String result = xorHex(portion, guessHex);

            // Convert result to ASCII and check if it looks like English
            String ascii = hexToAscii(result);
            if (looksLikeEnglish(ascii)) {
                System.out.printf("Position %d: Found possible match:%n", start/2);
                System.out.printf("  Result: %s%n", ascii);
            }
        }
    }

    private String hexToAscii(String hex) {
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            int value = Integer.parseInt(hex.substring(i, i + 2), 16);
            if (value >= 32 && value <= 126) {  // Printable ASCII range
                ascii.append((char)value);
            } else {
                ascii.append('?');
            }
        }
        return ascii.toString();
    }

    /**
     * Basic check if a string might be English text.
     * This is a simple heuristic that can be improved.
     */
    private boolean looksLikeEnglish(String text) {
        // Count printable characters and spaces
        int printable = 0;
        for (char c : text.toCharArray()) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' || c == '.' || c == ',') {
                printable++;
            }
        }
        // Consider it English-like if most characters are printable
        return printable > text.length() * 0.7;
    }

    /**
     * Displays the menu and handles user interaction.
     */
    public void showMenu() {
        List<XORPair> pairs = createCiphertextPairs();

        while (true) {
            System.out.println("\nCiphertext Analysis Menu");
            System.out.println("=======================");
            System.out.println("1. View loaded ciphertexts");
            System.out.println("2. View all XORed pairs");
            System.out.println("3. Test a plaintext guess");
            System.out.println("4. Exit");

            System.out.print("\nEnter your choice (1-4): ");

            try {
                int choice = scanner.nextInt();
                scanner.nextLine(); // Clear buffer

                switch (choice) {
                    case 1:
                        displayAllCiphertexts();
                        break;
                    case 2:
                        displayXORPairs(pairs);
                        break;
                    case 3:
                        handlePlaintextGuess(pairs);
                        break;
                    case 4:
                        System.out.println("Goodbye!");
                        return;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }
            } catch (InputMismatchException e) {
                System.out.println("Please enter a number between 1 and 4.");
                scanner.nextLine();
            }
        }
    }

    private void displayAllCiphertexts() {
        System.out.println("\nLoaded Ciphertexts:");
        for (int i = 0; i < ciphertexts.size(); i++) {
            System.out.printf("%d: %s%n", i, ciphertexts.get(i));
        }
    }

    private void displayXORPairs(List<XORPair> pairs) {
        System.out.println("\nXORed Ciphertext Pairs:");
        for (XORPair pair : pairs) {
            System.out.printf("Ciphertexts %d and %d: %s%n",
                    pair.index1, pair.index2, pair.xorResult);
        }
    }

    /**
     * Handles the plaintext guessing process.
     * Unlike our previous version that worked with individual ciphertexts,
     * this works with XORed pairs to eliminate key effects.
     */
    private void handlePlaintextGuess(List<XORPair> pairs) {
        System.out.println("\nEnter your plaintext guess (can be any length):");
        System.out.println("Tip: Try common English phrases, words, or patterns");

        String guess = scanner.nextLine();
        if (guess.isEmpty()) {
            System.out.println("Guess cannot be empty");
            return;
        }

        analyzeGuess(guess, pairs);
    }

    /**
     * Helper class to keep track of XORed ciphertext pairs.
     */
    private static class XORPair {
        final int index1;
        final int index2;
        final String xorResult;

        XORPair(int index1, int index2, String xorResult) {
            this.index1 = index1;
            this.index2 = index2;
            this.xorResult = xorResult;
        }
    }

    public static void main(String[] args) {
        CiphertextPairXOR analyzer = new CiphertextPairXOR();
        try {
            analyzer.loadCiphertexts();
            analyzer.showMenu();
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}