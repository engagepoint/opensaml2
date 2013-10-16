/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
Modified to use SHA-2 and SHA2PRNG instead of SHA-1 and SHA1PRNG
Not tested
 */

package org.opensaml.saml1.binding.artifact;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.RequestAbstractType;
import org.opensaml.saml1.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Builder of SAML 1, type 0x001, artifacts.
 */
public class SAML1ArtifactType0001Builder implements SAML1ArtifactBuilder<SAML1ArtifactType0001> {

    public static final String DIGEST_ALGORITHM = "SHA-2";
    public static final String RANDOM_ALGORITHM = "SHA2PRNG";
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAML1ArtifactType0001Builder.class);

    /** {@inheritDoc} */
    public SAML1ArtifactType0001 buildArtifact(byte[] artifact) {
        return SAML1ArtifactType0001.parseArtifact(artifact);
    }

    /** {@inheritDoc} */
    public SAML1ArtifactType0001 buildArtifact(
            SAMLMessageContext<RequestAbstractType, Response, NameIdentifier> requestContext, Assertion assertion) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] source = messageDigest.digest(requestContext.getLocalEntityId().getBytes());

            SecureRandom handleGenerator = SecureRandom.getInstance(RANDOM_ALGORITHM);
            byte[] assertionHandle = new byte[20];
            handleGenerator.nextBytes(assertionHandle);

            return new SAML1ArtifactType0001(source, assertionHandle);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("JVM does not support required cryptography algorithms: %s/%s.", DIGEST_ALGORITHM, RANDOM_ALGORITHM);
            log.error(errorMessage, e);
            throw new InternalError(errorMessage);
        }
    }
}