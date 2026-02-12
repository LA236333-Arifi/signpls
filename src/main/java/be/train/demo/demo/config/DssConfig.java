package be.train.demo.demo.config;

import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer.PdfBoxDefaultSignatureDrawerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DssConfig
{
    @Bean
    public PdfBoxSignatureService pdfBoxSignatureService()
    {
        PdfBoxSignatureDrawerFactory pdfBoxDefaultSignatureDrawerFactory = new PdfBoxDefaultSignatureDrawerFactory();
        return new PdfBoxSignatureService(PDFServiceMode.SIGNATURE,  pdfBoxDefaultSignatureDrawerFactory);
    }
}
