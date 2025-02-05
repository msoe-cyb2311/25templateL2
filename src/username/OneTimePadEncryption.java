package username;

import java.io.*;
import java.nio.file.*;

/**
 * One-Time Pad Encryption Program
 *
 * This program implements a one-time pad encryption system for English sentences.
 * It preserves case sensitivity and outputs in a format suitable for cryptanalysis.
 *
 * Usage: java OneTimePadEncryption "key sentence"
 * The key must be the same length as the plaintext in the input file.
 */
public class OneTimePadEncryption {
    private static final String DATA_DIR = "data";
    private static final String INPUT_FILE = "plaintext.txt";
    private static final String OUTPUT_FILE = "ciphertext.txt";

    /**
     * Validates that a string contains only ASCII printable characters
     * @param text the string to validate
     * @throws IllegalArgumentException if invalid characters are found
     */
    private static void validateText(String text, String fieldName) {
        for (char c : text.toCharArray()) {
            if (c < 32 || c > 126) {
                throw new IllegalArgumentException(
                        fieldName + " contains invalid character: " + (int)c
                );
            }
        }
    }

    /**
     * Performs XOR encryption/decryption
     * @param plaintext the text to encrypt
     * @param key the encryption key
     * @return encrypted/decrypted bytes
     */
    private static byte[] encrypt(byte[] plaintext, byte[] key) {
        if (plaintext.length != key.length) {
            throw new IllegalArgumentException(
                    "Key length (" + key.length + ") must match plaintext length (" + plaintext.length + ")"
            );
        }

        byte[] result = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            result[i] = (byte) (plaintext[i] ^ key[i]);
        }
        return result;
    }

    /**
     * Formats encrypted bytes as a continuous hex string
     * @param bytes the encrypted bytes
     * @return hex string without spaces or newlines
     */
    private static String formatHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    /**
     * Formats bytes as ASCII values for debugging
     * @param bytes the bytes to format
     * @return string showing ASCII values
     */
    private static String formatAscii(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        // Create table header
        result.append(String.format("%-12s %-12s %-12s%n", "Character", "Decimal", "Hex"));
        result.append("-".repeat(36)).append("\n");

        // Add each byte's information
        for (byte b : bytes) {
            int value = b & 0xFF;
            char c = (value >= 32 && value <= 126) ? (char)value : '·'; // Show dot for non-printable chars
            result.append(String.format("%-12c %-12d 0x%02X%n",
                    c,                // Character (or dot for non-printable)
                    value,           // Decimal value
                    value            // Hex value
            ));
        }
        return result.toString();
    }

    public static void main(String[] args) {
        try {
            // Validate command line arguments
            if (args.length != 1) {
                System.err.println("Usage: java OneTimePadEncryption \"key sentence\"");
                System.err.println("The key must be the same length as the plaintext.");
                System.exit(1);
            }

            // Get and validate key
            String keyString = args[0];
            validateText(keyString, "Key");
            byte[] key = keyString.getBytes();

            // Create data directory if needed
            Path dataDir = Paths.get(DATA_DIR);
            if (!Files.exists(dataDir)) {
                Files.createDirectory(dataDir);
            }

            // Read and validate plaintext
            Path inputPath = dataDir.resolve(INPUT_FILE);
            if (!Files.exists(inputPath)) {
                System.err.println("Please create " + inputPath + " with your plaintext message");
                System.exit(1);
            }

            String plaintext = Files.readString(inputPath).trim();
            validateText(plaintext, "Plaintext");
            byte[] plaintextBytes = plaintext.getBytes();

            // Validate lengths
            if (plaintextBytes.length != key.length) {
                System.err.println("Error: Key length must match plaintext length");
                System.err.println("Plaintext length: " + plaintextBytes.length);
                System.err.println("Key length: " + key.length);
                System.exit(1);
            }

            // Perform encryption
            byte[] encrypted = encrypt(plaintextBytes, key);

            // Generate outputs
            String hexOutput = formatHex(encrypted);
            String asciiOutput = formatAscii(encrypted);

            // Print to console with explanatory messages
            System.out.println("=== One-Time Pad Encryption Results ===\n");

            System.out.println("Original Input:");
            System.out.println("--------------");
            System.out.println("Plaintext: \"" + plaintext + "\"");
            System.out.println("\nPlaintext bytes in different formats:");
            System.out.println(formatAscii(plaintextBytes));

            System.out.println("\nEncryption Key:");
            System.out.println("--------------");
            System.out.println("Key: \"" + keyString + "\"");
            System.out.println("\nKey bytes in different formats:");
            System.out.println(formatAscii(key));

            System.out.println("\nEncrypted Result:");
            System.out.println("----------------");
            System.out.println("Result bytes in different formats:");
            System.out.println("The printable ASCII value range is from 32 to 126 (decimal)");
            System.out.println(formatAscii(encrypted));

            System.out.println("\nFinal ciphertext (hex string for cryptanalysis):");
            System.out.println(hexOutput);

            // Write to output file
            Files.write(dataDir.resolve(OUTPUT_FILE), hexOutput.getBytes());
            System.out.println("\nHex output written to: " + dataDir.resolve(OUTPUT_FILE));

        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error reading/writing files: " + e.getMessage());
            System.exit(1);
        }
    }
}