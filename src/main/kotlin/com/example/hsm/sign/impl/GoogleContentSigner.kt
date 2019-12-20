package com.example.hsm.sign.impl

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.security.GeneralSecurityException

/**
 * @author jmc90
 * @since 2019-10-29
 */
class GoogleContentSigner(
        private val keyPath: String,
        private val googleAuthorisationKeyFileName: String
) : ContentSigner {
    private val outputStream: ByteArrayOutputStream = ByteArrayOutputStream()
    private val sigAlgId: AlgorithmIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSAANDMGF1")

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return this.sigAlgId
    }

    override fun getOutputStream(): OutputStream {
        return this.outputStream
    }

    override fun getSignature(): ByteArray {
        try {
            val googleCloudKMS = GoogleCloudKMS()
            val kms = googleCloudKMS.createAuthorizedClient(this.googleAuthorisationKeyFileName)
            val signedAttributeSet = outputStream.toByteArray()

            return googleCloudKMS.signAsymmetric(signedAttributeSet, kms, this.keyPath)
        } catch (e: IOException) {
            e.printStackTrace()
            throw RuntimeException("Unable to sign with KMS")
        } catch (e: GeneralSecurityException) {
            e.printStackTrace()
            throw RuntimeException("Unable to sign with KMS")
        }
    }
}
