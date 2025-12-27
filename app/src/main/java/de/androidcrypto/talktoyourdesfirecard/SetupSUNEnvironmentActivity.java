package de.androidcrypto.talktoyourdesfirecard;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class SetupSUNEnvironmentActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = SetupSUNEnvironmentActivity.class.getName();

    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output;
    private TextInputLayout outputLayout;
    private Button moreInformation;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);


    /**
     * NFC handling
     */

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;
    private DesfireEv3 desfireEv3;
    private DesfireAuthenticateLegacy desfireD40;
    private FileSettings fileSettings;
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup_light_environment);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etSetupLightEnvironmentOutput);
        outputLayout = findViewById(R.id.etSetupLightEnvironmentOutputLayout);
        moreInformation = findViewById(R.id.btnSetupLightEnvironmentMoreInformation);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(SetupSUNEnvironmentActivity.this, getResources().getString(R.string.more_information_setup_light_environment));
            }
        });
    }

    private void runSetupSunEnvironment() {
        clearOutputFields();
        writeToUiAppend(output, "runSetupSunEnvironment");

        boolean success;
        byte[] errorCode;
        String errorCodeReason;

        // 1) Format PICC (select master, auth with default DES key, format)
        writeToUiAppend("step 1-3: format the PICC using default master settings");
        success = desfireD40.formatPicc();
        errorCode = desfireD40.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("format of the PICC SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("format of the PICC FAILURE, aborted", COLOR_RED);
            return;
        }

        // 4) Create NDEF application for SUN/SDM usage
        writeToUiAppend("step 4: create NDEF application for SUN/SDM");
        success = desfireEv3.createApplicationAesIso(
                DesfireEv3.NDEF_APPLICATION_IDENTIFIER,
                DesfireEv3.NDEF_ISO_APPLICATION_IDENTIFIER,
                DesfireEv3.NDEF_APPLICATION_DF_NAME,
                5
        );
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create NDEF application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create NDEF application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 5) Select NDEF application
        writeToUiAppend("step 5: select NDEF application");
        success = desfireEv3.selectApplicationIsoByDfName(DesfireEv3.NDEF_APPLICATION_DF_NAME);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select NDEF application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("select NDEF application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 6) Authenticate with NDEF application master key (AES default) to change keys
        writeToUiAppend("step 6: authenticate with NDEF application master key (AES default) to change keys");
        success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("authenticate with NDEF application master key for key change SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("authenticate with NDEF application master key for key change FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 7) Change RW key (key 1) to SUN_AES_KEY for SDM
        writeToUiAppend("step 7: change RW key (key 1) to SUN_AES_KEY for SDM");
        success = desfireEv3.changeApplicationKeyFull(
                Constants.APPLICATION_KEY_RW_NUMBER,
                (byte) 0x00,
                Constants.SUN_AES_KEY,
                Constants.APPLICATION_KEY_RW_AES_DEFAULT
        );
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("change RW key (key 1) to SUN_AES_KEY SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("change RW key (key 1) to SUN_AES_KEY FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 8) Create NDEF CC file (file 01) and NDEF data file (file 02, pre-enabled SDM)
        // Note: use createAStandardFile (without ISO file id) to avoid LENGTH_ERROR (0x7E)
        // on some DESFire EV3 variants when passing ISO file ids in the CREATE_STD_FILE command.
        writeToUiAppend("step 8: create NDEF CC (file 01) and NDEF data file (file 02)");
        success = desfireEv3.createAStandardFileIso(
        DesfireEv3.NDEF_FILE_01_NUMBER,
        DesfireEv3.NDEF_FILE_01_ISO_NAME,
        DesfireEv3.CommunicationSettings.Plain,
        DesfireEv3.NDEF_FILE_01_ACCESS_RIGHTS,
        DesfireEv3.NDEF_FILE_01_SIZE,   // 32
        false                            // preEnableSdm: CC には不要
        );
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create NDEF CC file SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create NDEF CC file FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            writeToUiAppend(desfireEv3.getLogData());
            return;
        }

        // ★ データファイル (file 02) はこれまで通り non-ISO 版でOK
        success = desfireEv3.createAStandardFile(
                DesfireEv3.NDEF_FILE_02_NUMBER,
                DesfireEv3.CommunicationSettings.Plain,
                DesfireEv3.NDEF_FILE_02_ACCESS_RIGHTS,
                DesfireEv3.NDEF_FILE_02_SIZE,
                true // preEnableSdm: allow SDM on this file
        );
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("create NDEF data file SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("create NDEF data file FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 9) Write NDEF CC to file 01
        writeToUiAppend("step 9: write NDEF CC to file 01");
        success = desfireEv3.writeToStandardFileNdefContainerPlain(DesfireEv3.NDEF_FILE_01_NUMBER);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("write NDEF CC SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("write NDEF CC FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 10) Write SUN URL template into NDEF data file 02
        final String sunUrlTemplate = "https://od-receive.onrender.com/sun?u=&c=&t=";
        writeToUiAppend("step 10: write SUN URL template to file 02");
        success = desfireEv3.writeToStandardFileUrlPlain(DesfireEv3.NDEF_FILE_02_NUMBER, sunUrlTemplate);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("write SUN URL template SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("write SUN URL template FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 11) Authenticate with application master AES key (default) before enabling SDM
        writeToUiAppend("step 11: authenticate with NDEF application master key (AES default)");
        success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("authenticate with NDEF application master key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("authenticate with NDEF application master key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        // 12) Calculate SDM offsets based on the actual NDEF-encoded data layout
        writeToUiAppend("step 12: calculate SDM offsets from SUN URL template");
        int encPiccDataOffset;
        int macOffset;
        try {
            byte[] ndefFileData = buildNdefFileDataForUrl(sunUrlTemplate);
            byte[] uEquals = "u=".getBytes(StandardCharsets.UTF_8);
            byte[] tEquals = "t=".getBytes(StandardCharsets.UTF_8);

            int uIndex = indexOfSubArray(ndefFileData, uEquals);
            int tIndex = indexOfSubArray(ndefFileData, tEquals);

            if (uIndex < 0 || tIndex < 0) {
                writeToUiAppendBorderColor("could not find 'u=' or 't=' inside NDEF data, aborted", COLOR_RED);
                return;
            }

            encPiccDataOffset = uIndex + 2; // start after "u="
            macOffset = tIndex + 2;         // start after "t="

            writeToUiAppend("ENC PICC data offset: " + encPiccDataOffset);
            writeToUiAppend("MAC offset: " + macOffset);
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception while calculating SDM offsets: " + e.getMessage(), COLOR_RED);
            return;
        }

        // 13) Enable SDM on NDEF data file (file 02) with UID+ReadCounter+CMAC in URL
        writeToUiAppend("step 13: enable SDM on NDEF data file (file 02)");
        // access rights matching NDEF_FILE_02_ACCESS_RIGHTS = 00EE (RW/CAR = 0/0, R/W = free)
        int keyRW = 0;
        int keyCar = 0;
        int keyR = 14;  // 'E' = free read
        int keyW = 14;  // 'E' = free write

        success = desfireEv3.changeFileSettingsNtag424Dna(
                DesfireEv3.NDEF_FILE_02_NUMBER,
                DesfireEv3.CommunicationSettings.Plain,
                keyRW,
                keyCar,
                keyR,
                keyW,
                true,
                encPiccDataOffset,
                macOffset,
                macOffset
        );
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("enable SDM on NDEF data file SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("enable SDM on NDEF data file FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend(output, "");
        writeToUiAppendBorderColor("SUN / NDEF setup finished, you can remove the tag", COLOR_GREEN);
        vibrateShort();
    }

    /**
     * Build the exact NDEF file data layout (including the 0x00 length prefix)
     * that writeToStandardFileUrlPlain() uses internally, for a given URL.
     */
    private byte[] buildNdefFileDataForUrl(String url) {
        NdefRecord ndefRecord = NdefRecord.createUri(url);
        NdefMessage ndefMessage = new NdefMessage(ndefRecord);
        byte[] ndefMessageBytesHeadless = ndefMessage.toByteArray();
        byte[] data = new byte[ndefMessageBytesHeadless.length + 2];
        data[0] = (byte) 0x00;
        data[1] = (byte) (ndefMessageBytesHeadless.length & 0xFF);
        System.arraycopy(ndefMessageBytesHeadless, 0, data, 2, ndefMessageBytesHeadless.length);
        return data;
    }

    /**
     * Find first occurrence of sub-array inside array, or -1 if not found.
     */
    private int indexOfSubArray(byte[] array, byte[] subArray) {
        if (array == null || subArray == null || subArray.length == 0 || subArray.length > array.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= array.length - subArray.length; i++) {
            for (int j = 0; j < subArray.length; j++) {
                if (array[i + j] != subArray[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private boolean createLightFileSet() {
        Log.d(TAG, "createLightFileSet");
        boolean createStandardFile00Full = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_00_FULL_NUMBER, Constants.LIGHT_STANDARD_FILE_00_FULL_ISO_FILE_ID, DesfireEv3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_00, 256, false);
        Log.d(TAG, "createStandardFile00Full result: " + createStandardFile00Full);
        boolean createCyclicRecordFileFull = desfireEv3.createACyclicRecordFileIso(Constants.LIGHT_CYCLIC_RECORD_FILE_01_FULL_NUMBER, Constants.LIGHT_CYCLIC_RECORD_FILE_01_FULL_ISO_FILE_ID, DesfireEv3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_01, 16, 5);
        Log.d(TAG, "createCyclicRecordFileFull result: " + createCyclicRecordFileFull);
        boolean createValueFile03Full = desfireEv3.createAValueFile(Constants.LIGHT_VALUE_FILE_03_FULL_NUMBER, DesfireEv3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_03, 0,2147483647, 0,false);
        Log.d(TAG, "createValueFileFull result: " + createValueFile03Full);
        boolean createStandardFile04Full = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_04_FULL_NUMBER, Constants.LIGHT_STANDARD_FILE_04_FULL_ISO_FILE_ID, DesfireEv3.CommunicationSettings.Full, Constants.LIGHT_FILE_ACCESS_RIGHTS_04, 256, false);
        Log.d(TAG, "createStandardFile04Full result: " + createStandardFile04Full);

        boolean createStandardFile31Plain = desfireEv3.createAStandardFileIso(Constants.LIGHT_STANDARD_FILE_31_PLAIN_NUMBER, Constants.LIGHT_STANDARD_FILE_31_PLAIN_ISO_FILE_ID , DesfireEv3.CommunicationSettings.Plain, Constants.LIGHT_FILE_ACCESS_RIGHTS_31, 32, false);
        Log.d(TAG, "createStandardFile31Plain result: " + createStandardFile31Plain);
        return true;
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        clearOutputFields();
        writeToUiAppend("NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }
                desfireEv3 = new DesfireEv3(isoDep); // true means all data is logged

                isDesfireEv3 = desfireEv3.checkForDESFireEv3();
                if (!isDesfireEv3) {
                    writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                    return;
                }
                desfireD40 = new DesfireAuthenticateLegacy(isoDep, false);

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);
                runSetupSunEnvironment();

            }
        } catch (IOException e) {
            writeToUiAppendBorderColor("IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }


    /**
     * section for UI elements
     */

    private void writeToUiAppend(String message) {
        writeToUiAppend(output, message);
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void writeToUi(TextView textView, String message) {
        runOnUiThread(() -> {
            textView.setText(message);
        });
    }

    private void writeToUiAppendBorderColor(String message, int color) {
        writeToUiAppendBorderColor(output, outputLayout, message, color);
    }

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    public void showDialog(Activity activity, String msg) {
        final Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setContentView(R.layout.logdata);
        TextView text = dialog.findViewById(R.id.tvLogData);
        //text.setMovementMethod(new ScrollingMovementMethod());
        text.setText(msg);
        Button dialogButton = dialog.findViewById(R.id.btnLogDataOk);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private void clearOutputFields() {
        runOnUiThread(() -> {
            output.setText("");
        });
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        outputLayout.setBoxStrokeColorStateList(myColorList);
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(SetupSUNEnvironmentActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}
