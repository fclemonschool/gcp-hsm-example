package com.example.hsm.sign.impl

import com.example.hsm.sign.Signature
import com.example.hsm.sign.Signature.Companion.certificationChain
import com.example.hsm.tsa.TSAClient
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.Attributes
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.*
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

/**
 * @author jmc90
 * @since 2019-11-01
 */
class HSMSignature(
        private var keyPath: String,
        private var googleAuthKeyFileName: String
) : Signature {
    override fun sign(content: InputStream): ByteArray {
        try {
            buildCertificateChain()

            val tsaClient = TSAClient(URL(
                    "http://~~~~~~~~~~~~~~~~~~"),
                    null,
                    null,
                    MessageDigest.getInstance("SHA-256")
            )

            val generator = CMSSignedDataGenerator()
            val certification = certificationChain[0] as X509Certificate
            generator.addSignerInfoGenerator(
                    JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build())
                            .build(GoogleContentSigner(keyPath, googleAuthKeyFileName), certification)
            )
            generator.addCertificates(JcaCertStore(listOf(*certificationChain)))
            val message = CMSProcessableInputStream(content)
            var signedData = generator.generate(message, false)

            signedData = addSignedTimeStamp(signedData, tsaClient)

            return signedData.encoded
        } catch (e: GeneralSecurityException) {
            throw IOException(e)
        } catch (e: CMSException) {
            throw IOException(e)
        } catch (e: OperatorCreationException) {
            throw IOException(e)
        }
    }

    private fun getCertificate(fileName: String): X509Certificate {
        val inputStream = javaClass.getResourceAsStream(fileName)
        val certFactory = CertificateFactory.getInstance("X.509")
        val certs = certFactory.generateCertificates(inputStream) as Collection<Certificate>
        return certs.iterator().next() as X509Certificate
    }

    private fun setCertificateChain(certiChain: Array<Certificate>) {
        certificationChain = certiChain
    }

    private fun buildCertificateChain() {
        val certificationChain = arrayOf<Certificate>(
                getCertificate("/certification/~~~~~.cer"), // certification file
                getCertificate("/certification/~~~~.cer"), // CA certification file
                getCertificate("/certification/~~~~~.crt"), // CA certification file
                getCertificate("/certification/~~~~~~.cer")) // CA certification file
        setCertificateChain(certificationChain)
    }

    private fun addSignedTimeStamp(signedData: CMSSignedData, tsaClient: TSAClient): CMSSignedData {
        val signerStore = signedData.signerInfos
        val newSigners = ArrayList<SignerInformation>()

        for (signer in signerStore.signers) {
            newSigners.add(signTimeStamp(signer, tsaClient))
        }
        return CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))
    }

    private fun signTimeStamp(signer: SignerInformation, tsaClient: TSAClient): SignerInformation {
        val unsignedAttributes = signer.unsignedAttributes

        var vector = ASN1EncodableVector()
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector()
        }

        val token = tsaClient.getTimeStampToken(signer.signature)
        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        val signatureTimeStamp = Attribute(oid,
                DERSet(ASN1Primitive.fromByteArray(token)))

        vector.add(signatureTimeStamp)
        val signedAttributes = Attributes(vector)
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes))
    }
}
