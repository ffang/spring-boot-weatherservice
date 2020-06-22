/**
 *  Copyright 2005-2016 Red Hat, Inc.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package io.fabric8.quickstarts.cxf.jaxws;

import java.util.HashMap;
import java.util.Map;

import javax.xml.ws.Endpoint;
import org.apache.cxf.Bus;
import org.apache.cxf.ext.logging.LoggingInInterceptor;
import org.apache.cxf.ext.logging.LoggingOutInterceptor;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.fabric8.quickstarts.camel.bridge.WeatherPortImpl;

@Configuration
public class WebServiceConfig {

    @Autowired
    private Bus bus;

    @Bean
    public Endpoint endpoint() {
        
        Object implementor = new WeatherPortImpl();
        EndpointImpl endpoint = new EndpointImpl(bus, implementor);
        

        EndpointImpl impl = (EndpointImpl)Endpoint.publish("/WeatherService", implementor);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put("action", "Timestamp SAMLTokenSigned");
        inProps.put("signatureVerificationPropFile", "/ws-security/bob.properties");
        impl.getProperties().put("ws-security.saml2.validator", "io.fabric8.quickstarts.camel.bridge.security.Saml2Validator");

        impl.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        impl.getInInterceptors().add(new LoggingInInterceptor());
        impl.getOutInterceptors().add(new LoggingOutInterceptor());
        return endpoint;
        
    }
}
