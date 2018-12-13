package com.demo.ssl;


import javax.net.ssl.*;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.*;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Troubleshooting SSL handshake issue
 * -----------------------------------
 * <p>
 * 3CE’s ssl connection supports:  TLSv1.2 and the below cipher suites as listed from the nmap command.
 * In order for a client to connect, the client & server should agree on the TLS version and
 * the cipher to be used during handshake. The handshake will fail if there is no agreement.
 * Since 3CE uses high strength ciphers, the client should enable unlimited strength policy.
 * In the most recent versions of JDK, high strength ciphers are enabled by default.
 * If you are getting the below error, its because the client & server cannot negotiate ssl.
 * <p>
 * " javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure "
 * <p>
 * To fix this via code, just add the below snippet right after the main method in Java.
 * <p>
 * Security.setProperty("crypto.policy", "unlimited");
 * <p>
 * If you are still having handshake errors after adding the below line,
 * then your JDK/JRE version may not be enabled for high strength ciphers by default.
 * <p>
 * Follow the instructions in the link below in such cases to enable
 * Unlimited Strength Jurisdiction Policy Files
 * <p>
 * http://opensourceforgeeks.blogspot.com/2014/09/how-to-install-java-cryptography.html
 * <p>
 * <p>
 * -----
 * nmap --script ssl-enum-ciphers -p 443 auth.3ce.com
 * <p>
 * Starting Nmap 7.01 ( https://nmap.org ) at 2018-12-11 12:08 EST
 * Nmap scan report for auth.xxxxxxxxxx.com (192.99.46.133)
 * Host is up (0.0025s latency).
 * 443/tcp open  https
 * | ssl-enum-ciphers:
 * |   TLSv1.2:
 * |     ciphers:
 * |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp384r1) - A
 * |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (secp384r1) - A
 * |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp384r1) - A
 * |       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 4096) - A
 * |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (dh 4096) - A
 * |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 4096) - A
 * |     compressors:
 * |       NULL
 * |     cipher preference: server
 * |_  least strength: A
 * <p>
 * Nmap done: 1 IP address (1 host up) scanned in 10.94 seconds
 */


/**
 * @author tito
 */
public class CCCESSLTestSelfSigned {

    public static final String CLASSIFICATION_API = "";
    public static final String ACCESSTOKEN_API = "";
    public static final String CONSUMER_CLIENT = "";
    public static final String CONSUMER_SECRET = "";
    public static final String API_USERNAME = "";
    public static final String API_PASSWORD = "";
    public static final String API_SCOPE = "";

    public static void main(String[] args) {
        /**
         * If you are still having handshake errors after adding the below line,
         * then your JDK/JRE version may not be enabled for high strength ciphers by default.
         *
         * Follow the instructions in the link below in such cases to enable
         * Unlimited Strength Jurisdiction Policy Files
         *
         *  http://opensourceforgeeks.blogspot.com/2014/09/how-to-install-java-cryptography.html
         *
         */
        Security.setProperty("crypto.policy", "unlimited");
        CCCESSLTestSelfSigned.makeSSLTrustedAndVerfied();
        CCCESSLTestSelfSigned test = new CCCESSLTestSelfSigned();
        //get the access token
        String accessTokenJSON = test.getAccessToken();
        if (!accessTokenJSON.isEmpty()) {
            printAcessTokenDetails(accessTokenJSON);
            //call classification API using the access token
            String classificationResult = test.testClassificationRequest(accessTokenJSON);
            if (!classificationResult.isEmpty()) {
                System.out.println(classificationResult);
            }
        }
    }

    private static void printAcessTokenDetails(String accessTokenJSON){

        Map<String, String> jsonMap = parseJSONToMap(accessTokenJSON);
        System.out.println("Access Token: "+ jsonMap.get("access_token"));
        System.out.println("Token Type: "+jsonMap.get("token_type"));
        System.out.println("Refresh Token: "+jsonMap.get("refresh_token"));
        System.out.println("Expires In: "+String.valueOf(jsonMap.get("expires_in")));
    }

    private String getAccessToken() {


        URL url;
        try {
            url = new URL(CCCESSLTestSelfSigned.ACCESSTOKEN_API);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Accept", "application/json");
            final String s = CCCESSLTestSelfSigned.CONSUMER_CLIENT + ":" + CCCESSLTestSelfSigned.CONSUMER_SECRET;
            final byte[] authBytes = s.getBytes(StandardCharsets.UTF_8);
            final String encoded = Base64.getEncoder().encodeToString(authBytes);
            con.setRequestProperty("Authorization", "Basic " + encoded);
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("grant_type", "password");
            params.put("username", CCCESSLTestSelfSigned.API_USERNAME);
            params.put("password", CCCESSLTestSelfSigned.API_PASSWORD);
            params.put("scope", CCCESSLTestSelfSigned.API_SCOPE);
            StringBuilder postData = new StringBuilder();
            for (Map.Entry<String, Object> param : params.entrySet()) {
                if (postData.length() != 0) postData.append('&');
                postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                postData.append('=');
                postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
            }
            byte[] postDataBytes = postData.toString().getBytes(StandardCharsets.UTF_8);
            con.setDoOutput(true);
            con.setDoInput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.write(postDataBytes);
            wr.flush();
            wr.close();
            int responseCode = con.getResponseCode();
            System.out.println("Sending 'POST' request to URL : " + url);
            System.out.println("Response Code : " + responseCode);
            if(responseCode == 401){
                System.err.println("Check your API credentials.");
            }
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            return response.toString();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (ProtocolException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    private static Map<String, String> parseJSONToMap(String json) {

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        Object jsonObj = null;
        try {
            jsonObj = engine.eval(String.format("JSON.parse('%s')", json));
        } catch (ScriptException e) {
            e.printStackTrace();
        }
        Map<String, String> map = (Map<String, String>) jsonObj;
        return map;
    }

    /**
     * Never use this in production. Only for testing & development purposes.
     *
     * The hostname verification is made to trust implicitly.
     * The intermediate self signed certificate chain validation
     * is made to trust all certificates.
     *
     */
    private static void makeSSLTrustedAndVerfied() {

        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(
                                X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(
                                X509Certificate[] certs, String authType) {
                        }
                    }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultHostnameVerifier((s, sslSession) -> true);
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }


    }

    private String testClassificationRequest(String accessToken) {

        Map<String, String> jsonMap = parseJSONToMap(accessToken);
        URL url;
        try {

            url = new URL(CCCESSLTestSelfSigned.CLASSIFICATION_API);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            con.setRequestProperty("Accept", "application/json");
            con.setRequestProperty("Authorization", "Bearer " + jsonMap.get("access_token"));
            String json = "{\"proddesc\":\"frozen durian\"}";
            con.setDoOutput(true);
            con.setDoInput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.write(json.getBytes(StandardCharsets.UTF_8));
            wr.flush();
            wr.close();
            int responseCode = con.getResponseCode();
            System.out.println("Sending 'POST' request to URL : " + url);
            System.out.println("Response Code : " + responseCode);
            if(responseCode == 401){
                System.err.println("Check your API credentials.");
            }
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            return response.toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

    /**
     * Use the below method to debug SSL handshake issues.
     */
    private void print_https_cert(HttpsURLConnection con) {

        if (con != null) {

            try {

                System.out.println("Response Code : " + con.getResponseCode());
                System.out.println("Cipher Suite : " + con.getCipherSuite());
                System.out.println("\n");

                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    System.out.println("Cert Type : " + cert.getType());
                    System.out.println("Cert Hash Code : " + cert.hashCode());
                    System.out.println("Cert Public Key Algorithm : "
                            + cert.getPublicKey().getAlgorithm());
                    System.out.println("Cert Public Key Format : "
                            + cert.getPublicKey().getFormat());
                    System.out.println("\n");
                }

            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

    private void print_content(HttpsURLConnection con) {
        if (con != null) {

            try {

                System.out.println("****** Content of the URL ********");
                BufferedReader br =
                        new BufferedReader(
                                new InputStreamReader(con.getInputStream()));

                String input;

                while ((input = br.readLine()) != null) {
                    System.out.println(input);
                }
                br.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

}
