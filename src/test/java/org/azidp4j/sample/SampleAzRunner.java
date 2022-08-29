package org.azidp4j.sample;

import com.nimbusds.jose.JOSEException;
import java.io.IOException;

public class SampleAzRunner {
    public static void main(String[] args) throws IOException, JOSEException {
        var az = new SampleAz();
        az.start(8080);
    }
}
