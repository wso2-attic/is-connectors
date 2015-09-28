Product: Template for WSO2 IS Provisioning Connector

STEPS:

 1. Navigate to "<IS_CONNECTORS_HOME>/org.wso2.carbon.provisioning.connector-archetype" and run the following command
         mvn clean install

 2. Run the following command to create the IS authenticator
        mvn archetype:generate
            -DarchetypeGroupId=org.wso2.carbon
            -DarchetypeArtifactId=org.wso2.carbon.provisioning.connector-archetype
            -DarchetypeVersion=4.2.0
            -DgroupId=org.wso2.carbon.identity
            -DartifactId=org.wso2.carbon.identity.provisioning.connector
            -Dversion=1.0.0

 3. Enter the provisioning connector name after executing steps 1 & 2. Please enter the connector name in upper camel case
     eg:- connector_name : : Salesforce

 4. Confirm the connector name
      Y : : Y