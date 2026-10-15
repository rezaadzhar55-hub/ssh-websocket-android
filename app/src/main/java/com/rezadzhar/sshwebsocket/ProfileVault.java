package com.rezadzhar.sshwebsocket;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class ProfileVault {
    private static final String PREFS = "ssh_ws_profile_vault";
    private static final String VALUE = "encrypted_profile";
    private static final String KEY_ALIAS = "ssh_ws_profile_aes_gcm_v1";
    private static final int IV_BYTES = 12;
    private ProfileVault() { }

    static void save(Context context, SshProfile profile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(), new java.security.SecureRandom());
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(profile.toJson().toString().getBytes(StandardCharsets.UTF_8));
        ByteBuffer packed = ByteBuffer.allocate(iv.length + ciphertext.length);
        packed.put(iv).put(ciphertext);
        preferences(context).edit().putString(VALUE,
                Base64.encodeToString(packed.array(), Base64.NO_WRAP)).apply();
    }

    static SshProfile load(Context context) throws Exception {
        String encoded = preferences(context).getString(VALUE, null);
        if (encoded == null || encoded.isEmpty()) return null;
        byte[] packed = Base64.decode(encoded, Base64.NO_WRAP);
        if (packed.length <= IV_BYTES) throw new IllegalStateException("Data profil tersimpan tidak lengkap.");
        byte[] iv = new byte[IV_BYTES];
        byte[] ciphertext = new byte[packed.length - IV_BYTES];
        ByteBuffer.wrap(packed).get(iv).get(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(128, iv));
        return SshProfile.fromJson(new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8));
    }

    static boolean exists(Context context) {
        return preferences(context).contains(VALUE);
    }

    static void clear(Context context) {
        preferences(context).edit().remove(VALUE).apply();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        java.security.Key existing = keyStore.getKey(KEY_ALIAS, null);
        if (existing instanceof SecretKey) return (SecretKey) existing;
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build();
        generator.init(spec);
        return generator.generateKey();
    }
}
