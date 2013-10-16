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

package org.opensaml.saml2.binding.artifact;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IndexedEndpoint;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * SAML 2, type 0x0004, artifact builder.
 */
public class SAML2ArtifactType0004Builder implements SAML2ArtifactBuilder<SAML2ArtifactType0004> {

    public static final String DIGEST_ALGORITHM = "SHA-2";
    public static final String RANDOM_ALGORITHM = "SHA2PRNG";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAML2ArtifactType0004Builder.class);

    /** {@inheritDoc} */
    public SAML2ArtifactType0004 buildArtifact(byte[] artifact) {
        return SAML2ArtifactType0004.parseArtifact(artifact);
    }

    /** {@inheritDoc} */
    public SAML2ArtifactType0004 buildArtifact(SAMLMessageContext<SAMLObject, SAMLObject, NameID> requestContext) {
        try {
            IndexedEndpoint acsEndpoint = (IndexedEndpoint) getAcsEndpoint(requestContext);
            if (acsEndpoint == null) {
                return null;
            }

            byte[] endpointIndex = DatatypeHelper.intToByteArray(acsEndpoint.getIndex());
            byte[] trimmedIndex = new byte[2];
            trimmedIndex[0] = endpointIndex[2];
            trimmedIndex[1] = endpointIndex[3];

            MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] source = messageDigest.digest(requestContext.getLocalEntityId().getBytes());

            SecureRandom handleGenerator = SecureRandom.getInstance(RANDOM_ALGORITHM);
            byte[] assertionHandle;
            assertionHandle = new byte[20];
            handleGenerator.nextBytes(assertionHandle);

            return new SAML2ArtifactType0004(trimmedIndex, source, assertionHandle);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("JVM does not support required cryptography algorithms: %s/%s.", DIGEST_ALGORITHM, RANDOM_ALGORITHM);
            log.error(errorMessage, e);
            throw new InternalError(errorMessage);
        }
    }

    /**
     * Gets the source location used to for the artifacts created by this encoder.
     *
     * @param requestContext current request context
     *
     * @return source location used to for the artifacts created by this encoder
     */
    protected Endpoint getAcsEndpoint(SAMLMessageContext<SAMLObject, SAMLObject, NameID> requestContext) {
        BasicEndpointSelector selector = new BasicEndpointSelector();
        selector.setEndpointType(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        selector.getSupportedIssuerBindings().add(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        selector.setMetadataProvider(requestContext.getMetadataProvider());
        selector.setEntityMetadata(requestContext.getLocalEntityMetadata());
        selector.setEntityRoleMetadata(requestContext.getLocalEntityRoleMetadata());

        Endpoint acsEndpoint = selector.selectEndpoint();

        if (acsEndpoint == null) {
            log.error("No artifact resolution service endpoint defined for the entity "
                    + requestContext.getOutboundMessageIssuer());
            return null;
        }

        return acsEndpoint;
    }
}