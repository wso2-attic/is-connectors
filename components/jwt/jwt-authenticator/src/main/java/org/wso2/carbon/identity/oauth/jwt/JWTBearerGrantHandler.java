/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.jwt.cache.JWTCache;
import org.wso2.carbon.identity.oauth.jwt.cache.JWTCacheEntry;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;


/**
 * Class to handle JSON Web Token(JWT) grant type
 */
public class JWTBearerGrantHandler extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(JWTBearerGrantHandler.class);

    private static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String OAUTH_JWT_ASSERTION = "assertion";
    private static final int VALIDITY_PERIOD = 30;
    private static final boolean CACHE_USED_JTI = true;
    private static String tenantDomain;
    private JWTCache jwtCache;

    /**
     * Initialize the JWT cache.
     *
     * @throws IdentityOAuth2Exception
     */
    public void init() throws IdentityOAuth2Exception {
        super.init();
        if (CACHE_USED_JTI) {
            this.jwtCache = JWTCache.getInstance();
        }
    }


    /**
     * We're validating the JWT token that we receive from the request. Through the assertion parameter is the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
     * &assertion=eyJhbGciOiJFUzI1NiJ9.
     * eyJpc3Mi[...omitted for brevity...].
     *
     * @param tokReqMsgCtx Token message request context
     * @return true if validation is successful, false otherwise
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        SignedJWT signedJWT;
        IdentityProvider identityProvider;
        String tokenEndPointAlias;
        ReadOnlyJWTClaimsSet claimsSet;

        tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();

        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        signedJWT = getSignedJWT(tokReqMsgCtx);
        if (signedJWT == null) {
            return false;
        }
        claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            return false;
        }

        String jwtIssuer = claimsSet.getIssuer();
        String subject = claimsSet.getSubject();
        List<String> audience = claimsSet.getAudience();
        Date expirationTime = claimsSet.getExpirationTime();
        Date notBeforeTime = claimsSet.getNotBeforeTime();
        Date issuedAtTime = claimsSet.getIssueTime();
        String jti = claimsSet.getJWTID();
        Map<String, Object> customClaims = claimsSet.getCustomClaims();
        boolean signatureValid;
        boolean audienceFound = false;
        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;

        if (StringUtils.isEmpty(jwtIssuer) || StringUtils.isEmpty(subject) || expirationTime == null) {
            log.error("Mandatory fields are empty in the JSON Web Token");
            return false;
        }

        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            if (identityProvider != null) {
                tokenEndPointAlias = getTokenEndpointAlias(identityProvider);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No Registered IDP found for the JWT with issuer name : " + jwtIssuer);
                }
                return false;
            }

            signatureValid = validateSignature(signedJWT, identityProvider);
            if (signatureValid) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature/MAC validated successfully");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature or Message Authentication invalid");
                    log.debug("JWT Rejected and validation terminated");
                }
                return false;
            }

            tokReqMsgCtx.setAuthorizedUser(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(subject));
            if (log.isDebugEnabled()) {
                log.debug("Subject(sub) found in JWT: " + subject);
                log.debug(subject + " set as the Authorized User");
            }

            if (StringUtils.isEmpty(tokenEndPointAlias)) {
                log.debug("Token End Point of the IDP is empty");
                return false;
            }
            for (String aud : audience) {
                if (StringUtils.equals(tokenEndPointAlias, aud)) {
                    if (log.isDebugEnabled()) {
                        log.debug(tokenEndPointAlias + " of IDP was found in the list of audiences");
                    }
                    audienceFound = true;
                    break;
                }
            }
            if (!audienceFound) {
                if (log.isDebugEnabled()) {
                    log.debug("None of the audience values matched the tokenEndpoint Alias " + tokenEndPointAlias);
                }
                return false;
            }
            if (checkExpirationTime(expirationTime, currentTimeInMillis, timeStampSkewMillis)) {
                if (log.isDebugEnabled()) {
                    log.debug("Expiration Time(exp) of JWT was validated successfully");
                }
            }

            if (checkNotBeforeTime(notBeforeTime, currentTimeInMillis, timeStampSkewMillis)) {
                if (log.isDebugEnabled()) {
                    log.debug("Not Before Time(nbf) of JWT was validated successfully");
                }
            }

            if (checkValidityOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis)) {
                if (log.isDebugEnabled()) {
                    log.debug("Issued At Time(iat) of JWT was validated successfully");
                }
            }

            if (jti != null) {
                JWTCacheEntry entry = (JWTCacheEntry) jwtCache.getValueFromCache(jti);
                if (entry != null) {
                    if (checkCachedJTI(jti, signedJWT, entry, currentTimeInMillis, timeStampSkewMillis)) {
                        if (log.isDebugEnabled()) {
                            log.debug("JWT id: " + jti + " not found in the cache");
                            log.debug("jti of the JWT has been validated successfully");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("JSON Web Token ID(jti) not found in JWT. Continuing Validation");
                }
            }

            if (customClaims == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No custom claims found. Continue validating other claims.");
                }
            } else {
                boolean customClaimsValidated = validateCustomClaims(claimsSet.getCustomClaims());
                if (!customClaimsValidated) {
                    if (log.isDebugEnabled()) {
                        log.debug("Custom Claims in the JWT were not validated");
                    }
                    return false;
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("JWT Token was validated successfully");
            }

            jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));

            if (log.isDebugEnabled()) {
                log.debug("JWT Token was added to the cache successfully");
            }
        } catch (IdentityProviderManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting the Federated Identity Provider ", e);
            }
        } catch (JOSEException e) {
            log.error("Error when verifying signature", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Issuer(iss) of the JWT validated successfully");
        }

        return true;
    }

    /**
     * @param tokReqMsgCtx
     * @return
     */
    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) {
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT;
        for (RequestParameter param : params) {
            if (param.getKey().equals(OAUTH_JWT_ASSERTION)) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(assertion)) {
            log.error("No Valid Assertion was found for " + OAUTH_JWT_BEARER_GRANT_TYPE);
            return null;
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            if (log.isDebugEnabled()) {
                logJWT(signedJWT);
            }

        } catch (ParseException e) {
            log.error("Error while parsing the JWT" + e.getMessage());
            return null;
        }
        return signedJWT;
    }

    /**
     * @param signedJWT
     * @return
     */
    private ReadOnlyJWTClaimsSet getClaimSet(SignedJWT signedJWT) {
        ReadOnlyJWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Error when trying to retrieve claimsSet from the JWT", e);
            return null;
        }
        return claimsSet;
    }

    /**
     * Get token endpoint alias
     *
     * @param identityProvider
     * @return
     */
    private String getTokenEndpointAlias(IdentityProvider identityProvider) {
        Property oauthTokenURL = null;
        String tokenEndPointAlias = null;
        if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName())) {
            try {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            } catch (IdentityProviderManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting Resident IDP :" + e.getMessage());
                }
            }

            FederatedAuthenticatorConfig[] fedAuthnConfigs =
                    identityProvider.getFederatedAuthenticatorConfigs();

            FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                    IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);

            if (oauthAuthenticatorConfig != null) {
                oauthTokenURL = IdentityApplicationManagementUtil.getProperty(
                        oauthAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
            }

            if (oauthTokenURL != null) {
                tokenEndPointAlias = oauthTokenURL.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Token End Point Alias of Resident IDP :" + tokenEndPointAlias);
                }
            }
        } else {
            tokenEndPointAlias = identityProvider.getAlias();
            if (log.isDebugEnabled()) {
                log.debug("Token End Point Alias of the Federated IDP: " + tokenEndPointAlias);
            }
        }
        return tokenEndPointAlias;
    }

    /**
     * The JWT MUST contain an exp (expiration) claim that limits the time window during which
     * the JWT can be used. The authorization server MUST reject any JWT with an expiration time
     * that has passed, subject to allowable clock skew between systems. Note that the
     * authorization server may reject JWTs with an exp claim value that is unreasonably far in the
     * future.
     *
     * @param expirationTime
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @return
     */
    private boolean checkExpirationTime(Date expirationTime, long currentTimeInMillis, long timeStampSkewMillis) {
        long expirationTimeInMillis = expirationTime.getTime();

        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JSON Web Token is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis);
                log.debug("JWT Rejected and validation terminated");
            }

            return false;
        }
        return true;
    }

    /**
     * The JWT MAY contain an nbf (not before) claim that identifies the time before which the
     * token MUST NOT be accepted for processing.
     *
     * @param notBeforeTime
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @return
     */
    private boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis) {
        long notBeforeTimeMillis = notBeforeTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JSON Web Token is used before Not_Before_Time." +
                        ", Not Before Time(ms) : " + notBeforeTimeMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis);
                log.debug("JWT Rejected and validation terminated");
            }
            return false;
        }
        return true;
    }

    /**
     * The JWT MAY contain an iat (issued at) claim that identifies the time at which the JWT was
     * issued. Note that the authorization server may reject JWTs with an iat claim value that is
     * unreasonably far in the past
     *
     * @param issuedAtTime
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @return
     */
    private boolean checkValidityOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis) {
        long issuedAtTimeMillis = issuedAtTime.getTime();
        long rejectBeforeMillis = VALIDITY_PERIOD * 60 * 1000;
        if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                rejectBeforeMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JSON Web Token is issued before the allowed time." +
                        ", Issued At Time(ms) : " + issuedAtTimeMillis +
                        ", Reject before limit(ms) : " + rejectBeforeMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis);
                log.debug("JWT Rejected and validation terminated");
            }
            return false;
        }
        return true;
    }

    /**
     * Method to check whether the JTI is already in the cache.
     *
     * @param jti
     * @param signedJWT
     * @param entry
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @return
     */
    private boolean checkCachedJTI(String jti, SignedJWT signedJWT, JWTCacheEntry entry, long currentTimeInMillis,
                                   long timeStampSkewMillis) {
        try {
            SignedJWT cachedJWT = entry.getJwt();
            long cachedJWTExpiryTimeMillis = cachedJWT.getJWTClaimsSet().getExpirationTime().getTime();
            if (currentTimeInMillis + timeStampSkewMillis > cachedJWTExpiryTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("JWT Token has been reused after the allowed expiry time : "
                            + cachedJWT.getJWTClaimsSet().getExpirationTime());
                }

                // Update the cache with the new JWT for the same JTI.
                this.jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
                if (log.isDebugEnabled()) {
                    log.debug("jti of the JWT has been validated successfully and cache updated");
                } else {
                    log.error("JWT Token \n" + signedJWT.getHeader().toJSONObject().toString() + "\n"
                            + signedJWT.getPayload().toJSONObject().toString() + "\n" +
                            "Has been replayed before the allowed expiry time : "
                            + cachedJWT.getJWTClaimsSet().getExpirationTime());
                    return false;
                }
            }
        } catch (ParseException e) {
            log.error("Unable to parse the cached jwt assertion : " + entry.getEncodedJWt(), e);
            return false;
        }
        return true;
    }

    /**
     * @param signedJWT the signedJWT to be logged
     */
    private void logJWT(SignedJWT signedJWT) {
        log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
        log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
        log.debug("Signature: " + signedJWT.getSignature().toString());
    }

    /**
     * Method to validate the signature of the JWT
     *
     * @param signedJWT signed JWT whose signature is to be verified
     * @param idp       Identity provider who issued the signed JWT
     * @return whether signature is valid, true if valid else false
     * @throws java.security.cert.CertificateException
     * @throws com.nimbusds.jose.JOSEException
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    private boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception {

        JWSVerifier verifier = null;
        X509Certificate x509Certificate;

        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            log.error(e.getMessage(), e);
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain);
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (log.isDebugEnabled()) {
            log.debug("Signature Algorithm found in the JWT Header: " + alg);
        }
        if (alg.indexOf("RS") == 0) {
            RSAPublicKey publicKey = (RSAPublicKey) x509Certificate.getPublicKey();
            verifier = new RSASSAVerifier(publicKey);
        } else if (alg.indexOf("ES") == 0) {
            // TODO support ECDSA signature verification
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm not supported yet : " + alg);
            }
        }
        if (verifier == null) {
            if (log.isDebugEnabled()) {
                log.error("Could create a signature verifier for algorithm type: " + alg);
            }
            return false;
        }

        return signedJWT.verify(verifier);
    }

    /**
     * Method to validate the claims other than
     * iss - Issuer
     * sub - Subject
     * aud - Audience
     * exp - Expiration Time
     * nbf - Not Before
     * iat - Issued At
     * jti - JWT ID
     * typ - Type
     * <p/>
     * in order to write your own way of validation and use the JWT grant handler,
     * you can extend this class and override this method
     *
     * @param customClaims a map of custom claims
     * @return whether the token is valid based on other claim values
     */
    protected boolean validateCustomClaims(Map< String, Object > customClaims) {
        return true;
    }

}

