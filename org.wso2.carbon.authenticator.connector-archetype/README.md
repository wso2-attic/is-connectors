Product: Template for WSO2 IS Authenticator

STEPS:

 1. Navigate to "<IS_CONNECTORS_HOME>/org.wso2.carbon.authenticator.connector-archetype" and run the following command
         mvn clean install

 2. Run the following command to create the IS authenticator
    mvn archetype:generate
        -DarchetypeGroupId=org.wso2.carbon
        -DarchetypeArtifactId=org.wso2.carbon.authenticator.connector-archetype
        -DarchetypeVersion=4.2.0
        -DgroupId=org.wso2.carbon.identity
        -DartifactId=org.wso2.carbon.identity.authenticator
        -Dversion=4.2.0