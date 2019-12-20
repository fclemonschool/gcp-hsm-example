package com.example.hsm

import com.example.hsm.sign.impl.HSMSignature
import com.example.hsm.validation.AddValidationInformation
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.springframework.boot.autoconfigure.SpringBootApplication
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.Security
import java.util.*
import kotlin.random.Random


@SpringBootApplication
class HsmApplication

fun main(args: Array<String>) {
    // runApplication<HsmApplication>(*args)

    /*val keyFile: InputStream = HsmApplication::class.java.getResourceAsStream("/certification/keystore.p12")
    val ks = KeyStore.getInstance("PKCS12")
    val password = "cubetmf".toCharArray()
    ks.load(keyFile, password)
    val alias: String = ks.aliases().nextElement()

    FileInputStream("D:/doc/hello.pdf").use { ism ->
        PDDocument.load(ism).use { doc ->
            FileOutputStream("D:/doc/hello2.pdf").use { os ->
                val sig = KeyFileSignature(ks, password, alias)
                val pdfSignature = PDSignature()
                pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
                pdfSignature.name = "cubeTMF"
                pdfSignature.location = "Republic of Korea"
                pdfSignature.signDate = Calendar.getInstance()
                pdfSignature.byteRange = intArrayOf(0, 0)

                doc.addSignature(pdfSignature, sig)
                doc.saveIncremental(os)
            }
        }
    }*/

    val randomFileName = UUID.randomUUID().toString() + Random.nextInt(10).toString()

    FileInputStream("D:/doc/hello0.pdf").use { ism ->
        PDDocument.load(ism).use { doc ->
            FileOutputStream("D:/doc/${randomFileName}.pdf").use { os ->
                val sig = HSMSignature("projects/~~~~~~/locations/~~~~~/keyRings/~~~~~~/cryptoKeys/~~~~/cryptoKeyVersions/~~~~",
                        "/certification/~~~~~~~~.json")

                val pdfSignature = PDSignature()
                pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
                pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
                pdfSignature.name = "sample"
                pdfSignature.location = "Republic of Korea"
                pdfSignature.signDate = Calendar.getInstance()
                pdfSignature.byteRange = intArrayOf(0, 0)

                doc.addSignature(pdfSignature, sig)
                doc.saveIncremental(os)

                // For LTV
                Security.addProvider(SecurityProvider.getProvider())
                val addOcspInformation = AddValidationInformation()
                val inFile = File("D:/doc/${randomFileName}.pdf")
                val name = inFile.name
                val substring = name.substring(0, name.lastIndexOf('.'))
                val outFile = File(inFile.parent, substring + "_ltv.pdf")
                addOcspInformation.validateSignature(inFile, outFile)
            }
        }
    }

    // convertToPDF("D:/CRS-P-85/Documents/YSH_01.CRF Completion Guideline_v1.0.docx", "D:/doc/${randomFileName}.pdf")
}

/*fun convertToPDF(docPath: String, pdfPath: String) {
    try {
        val doc: InputStream = FileInputStream(File(docPath))
        val document = XWPFDocument(doc)
        val options: PdfOptions = PdfOptions.create()
        val out: OutputStream = FileOutputStream(File(pdfPath))
        PdfConverter.getInstance().convert(document, out, options)
        println("Done")
    } catch (ex: FileNotFoundException) {
        println(ex.message)
    } catch (ex: IOException) {
        println(ex.message)
    }
}*/

/*fun convertToPDF(docPath: String, pdfPath: String) {
    try {
        val doc: InputStream = FileInputStream(File(docPath))
        val fopFactory = FopFactory.newInstance(File(docPath))

        val output = BufferedOutputStream(FileOutputStream(File(pdfPath)))

        try {
            val fop = fopFactory.newFop(MimeConstants.MIME_PDF, output)

            val factory = TransformerFactory.newInstance()
            val transformer = factory.newTransformer()
            val src = StreamSource(File(pdfPath))

            val res = SAXResult(fop.defaultHandler)
            transformer.transform(src, res)
        } finally {
            output.close()
        }
        println("Success!")
    } catch (ex: FileNotFoundException) {
        println(ex.message)
    } catch (ex: IOException) {
        println(ex.message)
    }
}*/
