#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
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

package ${package};

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;

public class ${connector_name}Authenticator extends AbstractApplicationAuthenticator {

    private static Log log = LogFactory.getLog(${connector_name}Authenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the
     * authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isTraceEnabled()) {
            log.trace("Inside ${connector_name}.canHandle()");
        }
        //Add you code here
        return false;

    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        //Add you code here
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        //Add your code here for UI fields
        return configProperties;
    }

    /**
     * this method are overridden for extra claim request to ${connector_name} end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            //Add you code here
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }
    /**
     * Get the friendly name of the Authenticator
     * @return name
     */
    @Override
    public String getFriendlyName() {
        return "${connector_name} ";
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return "${connector_name}";
    }

    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return null;
    }
}

