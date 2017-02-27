package aestextencryption.rsrc;

/**
 * This interface defines basic socket communication methods.
 * These methods provide means for sending and receiving (Object) messages,
 * integrity checking and byte encoding (TO BE IMPLEMENTED).
 *
 * Networking interface methods send() and receive()
 * meant for implementation with class variable
 * output and input socket streams.
 */
public interface Networking{

    /**
     * Send (Object) message se through output stream.
     * Output stream must be defined as class variable.
     * @param se - (Object) message to be sent
     * @return - true for success, false for failure
     */
    boolean send(Object se);

    /**
     * Receive (Object) message through input stream.
     * Input stream must be defined as class variable.
     * @return - returns received (Object) message
     */
    Object receive();

    /**
     * Uses @data as input to a hash function and returns
     * obtained digest.
     * @param data - data bytes to be hashed
     * @return - digest of @data
     */
    byte[] dataDigest(byte[] data);

    /**
     * Compares, with some condition, the digest @base with
     * the digest obtained from hashing @comp with messageDigest().
     * @param base - digest to use as comparison base
     * @param comp - byte[] wich digest should be compared
     * @return - true if condition holds, false otherwise
     */
    boolean compDigest(byte[] base, byte[] comp);

    /**
     * Method to encode byte[] data @enc to a String using, for example
     * a specific charset or using base 64 enconding.
     * @param enc - data bytes to be encoded
     * @return - String representation of encoded @enc
     */
    String encode(byte[] enc);

    /**
     * Used for decoding Strings encoded by the encode().
     * encode() complementary method.
     * @param dec - data string to be decoded
     * @return - byte[] representation of decoded @dec
     */
    byte[] decode(String dec);

}