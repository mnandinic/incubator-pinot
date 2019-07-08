/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.pinot.transport.conf;

import org.apache.commons.configuration.Configuration;

import io.netty.handler.ssl.SslHandler;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NettySSLConf {

    protected static Logger LOGGER = LoggerFactory.getLogger(NettySSLConf.class);

    private static final String KEYSTORE_FILE = "pinot.server.ssl.keystore.file";
    private static final String KEYSTORE_PASSWORD = "pinot.server.ssl.keystore.pass";
    private static final String TRUSTSTORE_FILE = "pinot.server.ssl.truststore.file";
    private static final String TRUSTSTORE_PASSWORD = "pinot.server.ssl.truststore.pass";
    private static final String CERT_PASSWORD = "pinot.server.ssl.cert.pass";

    private static final String PROTOCOL = "TLS";
    private static final String ALGORITHM_SUN_X509 = "SunX509";
    private static final String KEYSTORE_TYPE = "JKS";

    private String _keyStorePath;
    private String _keyStorePassword;
    private String _trustStorePath;
    private String _trustStorePassword;
    private String _certPassword;

    public NettySSLConf(Configuration config) throws IllegalArgumentException{
        if (!(config.containsKey(KEYSTORE_FILE) && config.containsKey(KEYSTORE_PASSWORD)
            && config.containsKey(TRUSTSTORE_FILE) && config.containsKey(TRUSTSTORE_PASSWORD))){
            throw new IllegalArgumentException("Config does not contain all required SSL parameters");
        }
        _keyStorePath = config.getString(KEYSTORE_FILE);
        _keyStorePassword = config.getString(KEYSTORE_PASSWORD);
        _trustStorePath = config.getString(TRUSTSTORE_FILE);
        _trustStorePassword = config.getString(TRUSTSTORE_PASSWORD);
        if (config.containsKey(CERT_PASSWORD)){
            _certPassword = config.getString(CERT_PASSWORD);
        } else {
            _certPassword = _trustStorePassword;
        }
    }

    public SslHandler generateSSLHandler(){
        KeyStore keyStore = null;
        InputStream keyStoreStream = null;
        KeyManager[] keyManagers = null;
        KeyStore trustStore = null;
        InputStream trustStoreStream = null;
        TrustManager[] trustManagers = null;
        SSLContext sslContext = null;
        try {
            keyStoreStream = new FileInputStream(new File(_keyStorePath));
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(keyStoreStream, _keyStorePassword.toCharArray());
        } catch (IOException e) {
            LOGGER.info("Failed to load keystore file");
        } catch (CertificateException e) {
            LOGGER.info("Failed to parse certificate (keystore)");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.info("SSL algorithm error (keystore)");
        } catch (KeyStoreException e) {
            LOGGER.info("Failed to parse keystore");
        }
        finally {
            try {
                keyStoreStream.close();
            } catch (Exception e) {
                LOGGER.info("Failed to initialize keystore reader");
            }
        }
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(ALGORITHM_SUN_X509);
            keyManagerFactory.init(keyStore, _certPassword.toCharArray());
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (Exception e){
            LOGGER.info("Error creating keymanager");
        }
        try {
            trustStoreStream = new FileInputStream(new File(_trustStorePath));
            trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
            trustStore.load(trustStoreStream, _trustStorePassword.toCharArray());
        }
        catch (IOException e) {
            LOGGER.info("Failed to load truststore file");
        } catch (CertificateException e) {
            LOGGER.info("Failed to parse certificate (truststore)");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.info("SSL algorithm error (truststore)");
        } catch (KeyStoreException e) {
            LOGGER.info("Failed to parse truststore");
        }
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(ALGORITHM_SUN_X509);
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (Exception e){
            LOGGER.info("Error creating keymanager");
        }
        try {
            sslContext = SSLContext.getInstance(PROTOCOL);
            sslContext.init(keyManagers, trustManagers, null);
        } catch (Exception e) {
            LOGGER.info("Failed to create SSL context");
        }
        try {
            SSLEngine sslEngine = sslContext.createSSLEngine();
            sslEngine.setUseClientMode(false);
            sslEngine.setNeedClientAuth(false);
            return new SslHandler(sslEngine, true);
        } catch (Exception e) {
            LOGGER.info("Failed to create SslHandler");
            return null;
        }
    }
}