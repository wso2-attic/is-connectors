/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.provisioning.connector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

public class Util {
    /**
     * Set the client certificate to Default SSL Context
     * @param certificateFile		File containing certificate (PKCS12 format)
     * @param certPassword			Password of certificate
     * @throws Exception
     */
    public static void setHttpsClientCert(String certificateFile, String certPassword)
            throws Exception {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            return;
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());
        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
    }
}
