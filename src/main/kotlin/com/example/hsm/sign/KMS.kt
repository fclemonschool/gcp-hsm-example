package com.example.hsm.sign

/**
 * @author jmc90
 * @since 2019-12-09
 */
interface KMS {
    fun createAuthorizedClient(googleAuthorisationKeyFileName: String): Any?

    fun signAsymmetric(message: ByteArray, client: Any?, keyPath: String): Any?
}
