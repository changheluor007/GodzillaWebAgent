/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

public class StandardSessionIdGenerator{
    private final Queue<SecureRandom> randoms = new ConcurrentLinkedQueue();
    private String secureRandomClass = null;
    private String secureRandomAlgorithm = "SHA1PRNG";
    private String secureRandomProvider = null;
    private String jvmRoute = "";
    private int sessionIdLength = 16;
    
    public String generateSessionId(String route) {

        byte random[] = new byte[16];
        int sessionIdLength = 16;

        // Render the result as a String of hexadecimal digits
        // Start with enough space for sessionIdLength and medium route size
        StringBuilder buffer = new StringBuilder(2 * sessionIdLength + 20);

        int resultLenBytes = 0;

        while (resultLenBytes < sessionIdLength) {
            getRandomBytes(random);
            for (int j = 0;
                 j < random.length && resultLenBytes < sessionIdLength;
                 j++) {
                byte b1 = (byte) ((random[j] & 0xf0) >> 4);
                byte b2 = (byte) (random[j] & 0x0f);
                if (b1 < 10) {
                    buffer.append((char) ('0' + b1));
                } else {
                    buffer.append((char) ('A' + (b1 - 10)));
                }
                if (b2 < 10) {
                    buffer.append((char) ('0' + b2));
                } else {
                    buffer.append((char) ('A' + (b2 - 10)));
                }
                resultLenBytes++;
            }
        }

        if (route != null && route.length() > 0) {
            buffer.append('.').append(route);
        }

        return buffer.toString();
    }
    protected void getRandomBytes(byte[] bytes) {
        SecureRandom random = (SecureRandom)this.randoms.poll();
        if (random == null) {
            random = this.createSecureRandom();
        }

        random.nextBytes(bytes);
        this.randoms.add(random);
    }
    private SecureRandom createSecureRandom() {
        SecureRandom result = null;
        long t1 = System.currentTimeMillis();
        if (this.secureRandomClass != null) {
            try {
                Class<?> clazz = Class.forName(this.secureRandomClass);
                result = (SecureRandom)clazz.getConstructor().newInstance();
            } catch (Exception var8) {
            }
        }

        boolean error = false;
        if (result == null) {
            try {
                if (this.secureRandomProvider != null && this.secureRandomProvider.length() > 0) {
                    result = SecureRandom.getInstance(this.secureRandomAlgorithm, this.secureRandomProvider);
                } else if (this.secureRandomAlgorithm != null && this.secureRandomAlgorithm.length() > 0) {
                    result = SecureRandom.getInstance(this.secureRandomAlgorithm);
                }
            } catch (NoSuchAlgorithmException var9) {
                error = true;
            } catch (NoSuchProviderException var10) {
                error = true;
            }
        }

        if (result == null && error) {
            try {
                result = SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException var7) {
            }
        }

        if (result == null) {
            result = new SecureRandom();
        }

        result.nextInt();
        long t2 = System.currentTimeMillis();
        if (t2 - t1 > 100L) {
        }

        return result;
    }
}

