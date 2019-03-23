package com.malakapps.keystore_signandverify

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.util.*
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {

    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keyPair: KeyPair
    private lateinit var signatureResult: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguardManager.isDeviceSecure) {
            Toast.makeText(this, "Secure lock screen hasn't set up.", Toast.LENGTH_LONG).show()
        }

        generateKey()

        signButton.setOnClickListener {
            signData()
        }

        verifyButton.setOnClickListener {
            verifyData()
        }
    }

    private fun generateKey() {
        val startDate = GregorianCalendar()
        val endDate = GregorianCalendar()
        endDate.add(Calendar.YEAR, 1)

        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)

        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
            setCertificateSerialNumber(BigInteger.valueOf(777))
            setCertificateSubject(X500Principal("CN=$KEY_ALIAS"))
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            setCertificateNotBefore(startDate.time)
            setCertificateNotAfter(endDate.time)
            setUserAuthenticationRequired(true)
            setUserAuthenticationValidityDurationSeconds(30)
            build()
        }

        keyPairGenerator.initialize(parameterSpec)

        keyPair = keyPairGenerator.genKeyPair()
    }

    private fun signData() {
        try {
            val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }

            val privateKey: PrivateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
            val signature: ByteArray? = Signature.getInstance("SHA256withRSA").run {
                initSign(privateKey)
                update("TestString".toByteArray())
                sign()
            }

            if (signature != null) {
                signatureResult = Base64.encodeToString(signature, Base64.DEFAULT)
                resultTextView.text = "Signed successfully"
            }

        } catch (e: UserNotAuthenticatedException) {
            showAuthenticationScreen()
        } catch(e: SignatureException) {
            showAuthenticationScreen()
        } catch (e: KeyPermanentlyInvalidatedException) {
            Toast.makeText(this, "Keys are invalidated.\n" + e.message, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    private fun verifyData() {
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        //If we need the public key just certificate.publicKey
        val certificate: Certificate? = keyStore.getCertificate(KEY_ALIAS)

        if (certificate != null) {
            val signature: ByteArray = Base64.decode(signatureResult, Base64.DEFAULT)
            val isValid: Boolean = Signature.getInstance("SHA256withRSA").run {
                initVerify(certificate)
                update("TestString".toByteArray())
                verify(signature)
            }

            if (isValid) {
                resultTextView.text = "Verified successfully"
            } else {
                resultTextView.text = "Verification failed"
            }
        }
    }

    private fun showAuthenticationScreen() {
        val intent: Intent? = keyguardManager.createConfirmDeviceCredentialIntent(null, null)
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_FOR_CREDENTIALS)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_CODE_FOR_CREDENTIALS) {
            if (resultCode == Activity.RESULT_OK) {
                signData()
            } else {
                Toast.makeText(this, "Authentication failed.", Toast.LENGTH_SHORT).show();
            }
        }
    }
}

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_ALIAS = "MalakappsKey"
private const val REQUEST_CODE_FOR_CREDENTIALS = 1