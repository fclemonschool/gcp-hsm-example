package com.example.hsm.sign

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.jackson2.JacksonFactory
import com.google.api.services.cloudkms.v1.CloudKMS
import com.google.api.services.cloudkms.v1.CloudKMSScopes

/**
 * @author jmc90
 * @since 2019-10-30
 */
interface GoogleSimpleSignable {
    fun createAuthorizedClient(googleAuthorisationKeyFileName: String): CloudKMS {
        val transport = NetHttpTransport()
        val jsonFactory = JacksonFactory()
        var credential = GoogleCredential.fromStream(javaClass.getResourceAsStream(googleAuthorisationKeyFileName), transport, jsonFactory)
        if (credential.createScopedRequired()) {
            credential = credential.createScoped(CloudKMSScopes.all())
        }
        return CloudKMS.Builder(transport, jsonFactory, credential)
                .setApplicationName("Example")
                .build()
    }

    fun signAsymmetric(message: ByteArray, client: CloudKMS, keyPath: String): ByteArray
}
