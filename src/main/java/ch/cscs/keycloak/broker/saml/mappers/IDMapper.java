/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.cscs.keycloak.broker.saml.mappers;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class IDMapper extends AbstractIdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    public static final String USER_ID_ATTRIBUTE = "user-id-attribute";
    public static final String USER_NAME_ATTRIBUTE = "user-name-attribute";

    static {

        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(USER_ID_ATTRIBUTE);
        property.setLabel("User ID Attribute");
        property.setHelpText("SAML attribute to use as the external user ID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("uid");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(USER_NAME_ATTRIBUTE);
        property.setLabel("Username Attribute");
        property.setHelpText("SAML attribute to use as the external username");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("uid");
        CONFIG_PROPERTIES.add(property);

    }

    public static final String PROVIDER_ID = "saml-id-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "SAML ID Mapper";
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        String userIDAttribute = mapperModel.getConfig().get(USER_ID_ATTRIBUTE);
        String usernameAttribute = mapperModel.getConfig().get(USER_NAME_ATTRIBUTE);

        if (userIDAttribute != null && !userIDAttribute.isEmpty()) {
            String userID = getAttribute(assertion, userIDAttribute);
            if (userID != null) {
                context.setId(userID);
            }
        }

        if (usernameAttribute != null && !usernameAttribute.isEmpty()) {
            String username = getAttribute(assertion, usernameAttribute);
            if (username != null) {
                context.setUsername(username);
                context.setModelUsername(username);
            }
        }

    }

    @Override
    public String getHelpText() {
        return "Use SAML attributes to determine external username and ID";
    }

    private String getAttribute(AssertionType assertion, String name) {

        String value = null;

        for (AttributeStatementType statement : assertion.getAttributeStatements()) {
            for (AttributeStatementType.ASTChoiceType choice : statement.getAttributes()) {
                AttributeType attr = choice.getAttribute();
                if (name.equals(attr.getName()) || name.equals(attr.getFriendlyName())) {
                    List<Object> attributeValue = attr.getAttributeValue();
                    if (attributeValue != null && !attributeValue.isEmpty()) {
                        value = attributeValue.get(0).toString();
                    }
                    break;
                }
            }
        }

        return value;

    }

}
