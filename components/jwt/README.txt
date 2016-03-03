Product: JWT Grant Type for OAuth2
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- Mac OSx 10.9
- WSO2 IS 5.1.0
- Java 1.7

Do the following:

Deploying and Configuring JWT grant-type artifacts:
1. Navigate to grant-type/org.wso2.carbon.identity.oauth2.grant.jwt and build.

2. Place org.wso2.carbon.identity.oauth2.grant.jwt jar in the <IS_HOME>/repository/component/lib directory.

3. To register the JWT grant type, configure the <IS_HOME>/repository/conf/identity/identity.xml file by adding a new entry under the <OAuth><SupportedGrantTypes> element. Add a unique identifier between the <GrantTypeName> tags as seen in the code block below.
	<SupportedGrantType>
       	    <GrantTypeName>urn:ietf:params:oauth:grant-type:jwt-bearer</GrantTypeName>
            <GrantTypeHandlerImplClass>org.wso2.carbon.identity.oauth.jwt.JWTBearerGrantHandler</GrantTypeHandlerImplClass>
      	    <GrantTypeValidatorImplClass>org.wso2.carbon.identity.oauth.jwt.JWTGrantValidator</GrantTypeValidatorImplClass>
        </SupportedGrantType>

