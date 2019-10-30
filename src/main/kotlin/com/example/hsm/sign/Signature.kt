package com.example.hsm.sign

import org.apache.pdfbox.io.IOUtils
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * @author jmc90
 * @since 2019-10-29
 */
class Signature(
        private val keyPath: String,
        private val googleAuthKeyFileName: String
) : SignatureInterface {
    private lateinit var certiChain: Array<Certificate>

    override fun sign(content: InputStream): ByteArray {
        try {
            buildCertificateChain()
            val generator = CMSSignedDataGenerator()
            val certi = this.certiChain[0] as X509Certificate
            val hsmSigner: ContentSigner = GoogleKMSContentSigner(keyPath, googleAuthKeyFileName)
            generator.addSignerInfoGenerator(
                    JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build())
                            .build(hsmSigner, certi)
            )
            generator.addCertificates(JcaCertStore(listOf(*this.certiChain)))
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

    private fun buildCertificateChain() {
        val certChain = arrayOf<Certificate>(
                getCertificate("/certification/~~~~~~~~.cer"), // certification file
                getCertificate("/certification/~~~~~~~~.cer")) // CA certification file
        setCertificateChain(certChain)
    }

    private fun getCertificate(fileName: String): X509Certificate {
        val inputStream = javaClass.getResourceAsStream(fileName)
        val certFactory = CertificateFactory.getInstance("X.509")
        val certs = certFactory.generateCertificates(inputStream) as Collection<Certificate>
        return certs.iterator().next() as X509Certificate
    }

    private fun setCertificateChain(certificateChain: Array<Certificate>) {
        this.certiChain = certificateChain
    }

    class CMSProcessableInputStream(
            private val inputStream: InputStream,
            private val contentType: ASN1ObjectIdentifier
    ) : CMSTypedData {
        internal constructor(ism: InputStream) : this(ism, ASN1ObjectIdentifier(CMSObjectIdentifiers.data.id))

        override fun getContent(): Any {
            return inputStream
        }

        override fun write(out: OutputStream) {
            IOUtils.copy(inputStream, out)
            inputStream.close()
        }

        override fun getContentType(): ASN1ObjectIdentifier {
            return contentType
        }
    }
}
