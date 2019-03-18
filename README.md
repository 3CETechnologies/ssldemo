# Unable to find valid certification path to requested target

```
javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

This is because the JVM cannot verify the certificate chain path with the certificates present in the java keystore. This happens when you are using self signed certificates for development purposes and the root certificate & intermediaries if any is not present in the java keystore. To fix the issue with self signed certificate, you can either import the root CA+intermediaries to your java keystore. Or bypass the certificate chain verification and hostname verification in your code as show in the sample code. But this not recommened for production. This should only be used for development purposes.

If you get this error from using a production url whose certificate are signed by a well know CA like Verisign or GoDaddy, then this means that: 

1. The well known CA's root certificate is not present in your JVM keystore. 
   The solution is goto the CA's certificate repository and install the root certificate in your JVM keystore.
   
2. The java client cannot verify the certificate chain leading to root certificate even though its present in your keystore.
   This is because the server did not provide the intermediate certificates during SSL handshake to client. Ideally, the server should provide the intermediate certificates. If the server is not able to do so, or if you are not in control of the server, then you can install the intermediate certificates in your keystore to fix this.
   
Site to check your SSL certificates and bundle intermediate certs : https://whatsmychaincert.com

## Issue with GoDaddy’s SSL certs and Java

https://tozny.com/blog/godaddys-ssl-certs-dont-work-in-java-the-right-solution


# Troubleshooting SSL handshake issue


 3CE’s ssl connection supports:  TLSv1.2 and the below cipher suites as listed from the nmap command.
 In order for a client to connect, the client & server should agree on the TLS version and
 the cipher to be used during handshake. The handshake will fail if there is no agreement.
 Since 3CE uses high strength ciphers, the client should enable unlimited strength policy.
 In the most recent versions of JDK, high strength ciphers are enabled by default.
 If you are getting the below error, its because the client & server cannot negotiate ssl.
 
```
javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure
```

 To fix this via code, just add the below snippet right after the main method in Java.
 
```
     Security.setProperty("crypto.policy", "unlimited");
```

 If you are still having handshake errors after adding the below line,
 then your JDK/JRE version may not be enabled for high strength ciphers by default.

 Follow the instructions in the link below in such cases to enable
 Unlimited Strength Jurisdiction Policy Files

 http://opensourceforgeeks.blogspot.com/2014/09/how-to-install-java-cryptography.html


```
 nmap --script ssl-enum-ciphers -p 443 auth.3ce.com

 Starting Nmap 7.01 ( https://nmap.org ) at 2018-12-11 12:08 EST
 Nmap scan report for auth.3ce.com (192.99.46.133)
 Host is up (0.0025s latency).
 rDNS record for 192.99.46.133: ns500552.ip-192-99-46.net
 PORT    STATE SERVICE
 443/tcp open  https
 | ssl-enum-ciphers:
 |   TLSv1.2:
 |     ciphers:
 |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp384r1) - A
 |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (secp384r1) - A
 |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp384r1) - A
 |       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 4096) - A
 |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (dh 4096) - A
 |       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 4096) - A
 |     compressors:
 |       NULL
 |     cipher preference: server
 |_  least strength: A

 Nmap done: 1 IP address (1 host up) scanned in 10.94 seconds

```
