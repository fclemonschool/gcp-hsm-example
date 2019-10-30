package com.example.hsm.sign

import com.google.api.services.cloudkms.v1.CloudKMS
import com.google.api.services.cloudkms.v1.model.AsymmetricSignRequest
import com.google.api.services.cloudkms.v1.model.Digest
import java.security.MessageDigest
import java.util.*

/**
 * @author jmc90
 * @since 2019-10-29
 */
object GoogleKMSSimpleSign : GoogleSimpleSignable {

    override fun signAsymmetric(message: ByteArray, client: CloudKMS, keyPath: String): ByteArray {
        val digest = Digest()
        digest.encodeSha256(MessageDigest.getInstance("SHA-256").digest(message))
        return doSign(client, keyPath, digest)
    }

    private fun doSign(client: CloudKMS, keyPath: String, digest: Digest): ByteArray {
        val signRequest = AsymmetricSignRequest()
        signRequest.digest = digest

        val response = client.projects()
                .locations()
                .keyRings()
                .cryptoKeys()
                .cryptoKeyVersions()
                .asymmetricSign(keyPath, signRequest)
                .execute()
        return Base64.getMimeDecoder().decode(response.signature)
    }
}
