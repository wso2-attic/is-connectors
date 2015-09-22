Provisioning Connector Template

#Build the this project
org.wso2.carbon.provisioning.connector-archetype $mvn clean install

#Run the following command to create the IS provisioning connector
mvn archetype:generate
    -DarchetypeGroupId=org.wso2.carbon
    -DarchetypeArtifactId=org.wso2.carbon.provisioning.connector-archetype
    -DarchetypeVersion=4.2.0
    -DgroupId=org.wso2.carbon.identity
    -DartifactId=org.wso2.carbon.identity.provisioning.connector
    -Dversion=4.2.0
