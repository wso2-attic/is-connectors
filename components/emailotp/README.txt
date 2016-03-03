Steps to run

1.  Build the org.wso2.carbon.identity.application.authentication.endpoint.emailotp and copy the emailotpauthenticationendpoint.war to <IS-HOME>/repository/deployment/server/webapps/

2.  Update or Introduce the properties in emailprovider properties file at location <EMAILOTP_AUTHENTICATOR_HOME>/org.wso2.carbon.identity.authenticator/src/main/resources.

    Following (i), (ii), (iii), (iv), (v), (viii), (ix), (x), (xi) & (xii) property names should have the API name as prefix.

    (i)    Define Client Id with the API name.
               E.g: ClientId of Gmail API should be defined as GmailClientId=501390351749-ftjrp3ld9da4ohd1rulogejscpln646s.apps.googleusercontent.com

    (ii)   Define Client Secret with the API name.
               E.g: ClientSecret of Gmail API should be defined as GmailClientSecret=dj4st7_m3AcleMZR1weFNo1V

    (iii)  Define API Key with the API name.
               E.g: APIKey of Sendgrid API should be defined as SendgridAPIKey=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

    (iv)   Define Refresh Token with the API name.
               E.g: RefreshToken of Gmail API should be defined as GmailRefreshToken=1/YgNiepY107SyzJdgpynmf-eMYP4qYTPNG_L73MXfcbU

    (v)    Define the endpoint with the API name.
               E.g: Endpoint of Sendgrid API should be defined as SendgridEmailEndpoint=https://api.sendgrid.com/api/mail.send.json

    (vi)   accessTokenRequiredAPIs - Put all API names of Access Token required APIs as comma separated.
               E.g: accessTokenRequiredAPIs=Gmail

    (vii)  apiKeyHeaderRequiredAPIs - Put all API names as comma separated, If we need to send API Keys in header.
               E.g: apiKeyHeaderRequiredAPIs=Sendgrid

    (viii) Define the payload template.
               E.g: MandrillPayload={"key":"<API_KEY>","message":{"from_email":"<FROM_EMAIL>","to":[{"email":"<TO_EMAIL>"}],"subject":"OTP Code","text":"<BODY>"}}

    (ix)   Define the string to identify the failure.
               E.g: MandrillFailure="status":"rejected"
               If we get '"status":"rejected"' in the response body of Mandrill call, the mail has not been sent.

    (x)    Define the payload template.
               E.g: SendgridFormData=to=<TO_EMAIL>&from=<FROM_EMAIL>&subject=OTP Code&html=<BODY>

    (xi)   Define the URL parameters with the API name.
               E.g: SendgridURLParams=

    (xi)   Define the auth endpoint to get Access Token from Refresh Token.
               E.g: GmailTokenEndpoint=https://www.googleapis.com/oauth2/v3/token

    (xii)  Define the Authorization token type.
               E.g: SendgridAuthTokenType=Bearer

3.  Build the <EMAILOTP_AUTHENTICATOR_HOME>/org.wso2.carbon.identity.authenticator & copy the org.wso2.carbon.identity.authenticator.emailotp-1.0.0.jar
    to <IS-HOME>/repository/components/dropins

4.  Follow the steps in https://docs.wso2.com/display/ISCONNECTORS/Configuring+EmailOTP+Authenticator