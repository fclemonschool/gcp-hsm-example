package com.example.hsm.csr

import com.example.hsm.sign.GoogleKMSContentSigner
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.security.auth.x500.X500Principal

/**
 * @author jmc90
 * @since 2019-10-30
 */
@Suppress("JAVA_CLASS_ON_COMPANION")
class GCPGenerateCSR {
    companion object {
        private fun getPublicKey(): PublicKey {
            val lines = javaClass.getResourceAsStream("/certification/~~~~~~~.pub")
                    .bufferedReader(StandardCharsets.US_ASCII).readLines() as MutableList
            // val lines = Files.readAllLines(Paths.get("C:/key/~~~~~.pub"), StandardCharsets.US_ASCII)
            require(lines.size >= 2) { "Insufficient input" }
            require(lines.removeAt(0).startsWith("--")) { "Expected header" }
            require(lines.removeAt(lines.size - 1).startsWith("--")) { "Expected footer" }
            val raw = Base64.getDecoder().decode(lines.joinToString(""))
            val factory = KeyFactory.getInstance("RSA")
            return factory.generatePublic(X509EncodedKeySpec(raw))
        }

        @JvmStatic
        fun main(args: Array<String>) {
            val p10Builder = JcaPKCS10CertificationRequestBuilder(
                    X500Principal("CN=, O=, OU=, C=, L=, ST=, Email="), getPublicKey())

            val signer = GoogleKMSContentSigner("projects/~~~~~~~~~~~~/locations/~~~~~~~/keyRings/~~~~/cryptoKeys/~~~/cryptoKeyVersions/~",
                    "/certification/~~~~~~~~~~~~~~~~")
            val csr = p10Builder.build(signer)

            val pemObject = PemObject("CERTIFICATE REQUEST", csr.encoded)
            val csrString = StringWriter()
            val pemWriter = JcaPEMWriter(csrString)
            pemWriter.writeObject(pemObject)
            pemWriter.close()
            csrString.close()
            println(csrString) // console export csr string
        }
    }
}
