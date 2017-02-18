package aestextencryption.rsrc;

import java.io.IOException;
import java.io.ObjectInputStream;

public class ReceiveThread extends Thread{

    public ObjectInputStream in;
    public SessionEnvelope msg = null;
    public boolean END_THREAD = false;

    public ReceiveThread(ObjectInputStream obis){
        super("1");
        in = obis;
    }

    @Override
    public synchronized void run(){
        while (!END_THREAD) {
            try {
                msg = (SessionEnvelope) in.readObject();
                if (msg != null)
                    wait();
            } catch (IOException ioex) {
                ioex.printStackTrace();
            } catch (ClassNotFoundException cnfex) {
                cnfex.printStackTrace();
            } catch (NullPointerException npex) {
                npex.printStackTrace();
            } catch (InterruptedException intex) {
                intex.printStackTrace();
            }
        }

    }

    public void threadWait(int time){
        try {
            Thread.sleep(time); //Wait for message to be received
        } catch(InterruptedException intex){
            intex.printStackTrace();
        }
    }

    public synchronized void threadStop(){
        notify();
        this.END_THREAD = true;
    }

}