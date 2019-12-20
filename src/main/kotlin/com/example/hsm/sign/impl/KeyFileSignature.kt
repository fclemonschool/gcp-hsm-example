package com.example.hsm.sign.impl

import com.example.hsm.sign.Signature
import com.example.hsm.sign.Signature.Companion.appCertificateAlias
import com.example.hsm.sign.Signature.Companion.certificationChain
import com.example.hsm.sign.Signature.Companion.keyStore
import com.example.hsm.sign.Signature.Companion.keyStorePassword
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.IOException
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*

/**
 * @author jmc90
 * @since 2019-11-01
 */
class KeyFileSignature(
        private var keyStoreInput: KeyStore,
        private var keyStorePasswordInput: CharArray,
        private var appCertificateAliasInput: String
) : Signature {
    override fun sign(content: InputStream): ByteArray {
        try {
            keyStore = keyStoreInput
            keyStorePassword = keyStorePasswordInput
            appCertificateAlias = appCertificateAliasInput
            certificationChain = Optional.ofNullable(keyStore.getCertificateChain(appCertificateAlias))
                    .orElseThrow {
                        IOException("Cannot find Certificate Chain")
                    }

            val certificate = certificationChain[0]
            if (certificate is X509Certificate) {
                certificate.checkValidity()
            }

            val generator = CMSSignedDataGenerator()
            val certification = certificationChain[0] as X509Certificate
            val sha1Signer = JcaContentSignerBuilder("SHA256WithRSA")
                    .build(keyStore.getKey(appCertificateAlias, keyStorePassword) as PrivateKey?)
            generator.addSignerInfoGenerator(
                    JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build())
                            .build(sha1Signer, certification)
            )
            generator.addCertificates(JcaCertStore(listOf(*certificationChain)))
            val message = CMSProcessableInputStream(content)
            val signedData = generator.generate(message, false)
            return signedData.encoded
        } catch (e: GeneralSecurityException) {
            throw IOException(e)
        } catch (e: CMSException) {
            throw IOException(e)
        } catch (e: OperatorCreationException) {
            throw IOException(e)
        }
    }
}
