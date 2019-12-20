package com.example.hsm.sign

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import java.security.KeyStore
import java.security.cert.Certificate

/**
 * @author jmc90
 * @since 2019-10-29
 */

interface Signature : SignatureInterface {
    companion object {
        lateinit var keyStore: KeyStore
        lateinit var keyStorePassword: CharArray
        lateinit var appCertificateAlias: String
        lateinit var certificationChain: Array<Certificate>
    }
}
