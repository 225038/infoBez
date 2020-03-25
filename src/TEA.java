import java.io.FileReader;
import java.io.IOException;

public class TEA {
    private final static int FOR_ENCRYPT = 0x9E3779B9;
    private final static int ROUNDS = 32;
    private final static int FOR_DECRYPT = 0xC6EF3720;

    private int[] subKeys = new int[4];

    public TEA(byte[] key) {
        if (key == null)
            throw new RuntimeException("Invalid key: Key was null");
        if (key.length < 16)
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        for (int off = 0, i = 0; i < 4; i++) {
            subKeys[i] = ((key[off++] & 0xff)) |
                    ((key[off++] & 0xff) << 8) |
                    ((key[off++] & 0xff) << 16) |
                    ((key[off++] & 0xff) << 24);
        }
    }

    public byte[] encrypt(byte[] origin) {
        int paddedSize = ((origin.length / 8) + (((origin.length % 8) == 0) ? 0 : 1)) * 2;
        int[] buffer = new int[paddedSize + 1];

        buffer[0] = origin.length;

        pack(origin, buffer, 1);
        tea(buffer);

        return unpack(buffer, 0, buffer.length * 4);
    }

    public byte[] decrypt(byte[] crypt) {
        assert crypt.length % 4 == 0;
        assert (crypt.length / 4) % 2 == 1;
        int[] buffer = new int[crypt.length / 4];

        pack(crypt, buffer, 0);
        unTea(buffer);

        return unpack(buffer, 1, buffer[0]);
    }

    void tea(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;

        while (i < buf.length) {
            n = ROUNDS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = 0;

            while (n-- > 0) {
                sum += FOR_ENCRYPT;
                v0 += ((v1 << 4) + subKeys[0] ^ v1) + (sum ^ (v1 >>> 5)) + subKeys[1];
                v1 += ((v0 << 4) + subKeys[2] ^ v0) + (sum ^ (v0 >>> 5)) + subKeys[3];
            }

            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

    void unTea(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;

        while (i < buf.length) {
            n = ROUNDS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = FOR_DECRYPT;

            while (n-- > 0) {
                v1 -= ((v0 << 4) + subKeys[2] ^ v0) + (sum ^ (v0 >>> 5)) + subKeys[3];
                v0 -= ((v1 << 4) + subKeys[0] ^ v1) + (sum ^ (v1 >>> 5)) + subKeys[1];
                sum -= FOR_ENCRYPT;
            }

            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

    void pack(byte[] src, int[] dest, int destOffset) {
        assert destOffset + (src.length / 4) <= dest.length;
        int i = 0, shift = 24;
        int j = destOffset;

        dest[j] = 0;

        while (i < src.length) {
            dest[j] |= ((src[i] & 0xff) << shift);
            if (shift == 0) {
                shift = 24;
                j++;
                if (j < dest.length) dest[j] = 0;
            } else {
                shift -= 8;
            }
            i++;
        }
    }

    byte[] unpack(int[] src, int srcOffset, int destLength) {
        assert destLength <= (src.length - srcOffset) * 4;
        byte[] dest = new byte[destLength];
        int i = srcOffset;
        int count = 0;

        for (int j = 0; j < destLength; j++) {
            dest[j] = (byte) ((src[i] >> (24 - (8 * count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }

        return dest;
    }

    public static void main(String[] args) {
        /* Create a cipher using the first 16 bytes of the passphrase */
        TEA tea = new TEA("This is our key phrase!".getBytes());
        String encryptString = "";
        String decryptString = "";
        String originalString = "";

        try (FileReader reader = new FileReader("file.txt")) {
            char[] buf = new char[8];
            int c;

            while ((c = reader.read(buf)) > 0) {

                if (c < 8) {
                    // Дополняем до 8 символов (64 бит)
                    for (; c < 8; c++) {
                        buf[c] = ' ';
                    }
                }

                byte[] original = new String(buf).getBytes();
                byte[] crypt = tea.encrypt(original);
                byte[] result = tea.decrypt(crypt);

                originalString += new String(buf);
                encryptString += new String(crypt);
                decryptString += new String(result);
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }

        System.out.println("Original: " + originalString);
        System.out.println("Encrypt: " + encryptString);
        System.out.println("Decrypt: " + decryptString);
    }
}