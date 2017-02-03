package aestextencryption.rsrc;

/**
 * Networking interface methods send() and receive()
 * meant for implementation with class variable
 * output and input socket streams.
 */
public interface Networking{

    /**
     * Send (Object) message se through output stream.
     * Output stream must be defined as class variable.
     * @param se - (Object) message to be sent
     */
    void send(Object se);

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
    byte[] messageDigest(byte[] data);

    /**
     * Compares, with some condition, the digest @base with
     * the digest obtained from hashing @comp with messageDigest().
     * @param base - digest to use as comparison base
     * @param comp - byte[] wich digest should be compared
     * @return - true if condition holds, false otherwise
     */
    boolean compDigest(byte[] base, byte[] comp);
}