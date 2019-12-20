package com.example.hsm.sign.impl

import com.example.hsm.sign.KMS
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.jackson2.JacksonFactory
import com.google.api.services.cloudkms.v1.CloudKMS
import com.google.api.services.cloudkms.v1.CloudKMSScopes
import com.google.api.services.cloudkms.v1.model.AsymmetricSignRequest
import com.google.api.services.cloudkms.v1.model.Digest
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

/**
 * @author jmc90
 * @since 2019-12-20
 */
class GoogleCloudKMS: KMS {
    private val log = LoggerFactory.getLogger(GoogleCloudKMS::class.java)
    override fun createAuthorizedClient(googleAuthorisationKeyFileName: String): CloudKMS? {
        val transport = NetHttpTransport()
        val jsonFactory = JacksonFactory()
        var credential = GoogleCredential.fromStream(GoogleCloudKMS::class.java.getResourceAsStream(googleAuthorisationKeyFileName), transport, jsonFactory)
        if (credential.createScopedRequired()) {
            credential = credential.createScoped(CloudKMSScopes.all())
        }
        return CloudKMS.Builder(transport, jsonFactory, credential).setApplicationName("sample").build()
    }

    override fun signAsymmetric(message: ByteArray, client: Any?, keyPath: String): ByteArray {
        val digest = Digest()
        try {
            digest.encodeSha256(MessageDigest.getInstance("SHA-256").digest(message))
        } catch (e: NoSuchAlgorithmException) {
            log.error("signAsymmetric Error", e)
        }
        return doSign(client as CloudKMS, keyPath, digest)
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
