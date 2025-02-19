package com.thegbfoods.aica_rca_java;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.microsoft.graph.serviceclient.GraphServiceClient;

public class GraphService {
    private static GraphService _instance;
    private static ClientSecretCredential _clientSecretCredential;
    private static GraphServiceClient _appClient;

    private GraphService() throws Exception {
        try {
            InitGraph();
        } catch (Exception e) {
            throw e;
        }
    }

    public static GraphService GetInstance() throws Exception {
        if (_instance == null) {
            synchronized (GraphService.class) {
                if (_instance == null) {
                    try {
                        _instance = new GraphService();
                    } catch (Exception e) {
                        throw e;
                    }
                }
            }
        }
        return _instance;
    }

    private static void InitGraph() throws Exception {
        // Request the .default scope as required by app-only auth
        final String[] graphScopes = new String[] {"https://graph.microsoft.com/.default"};

        if (_clientSecretCredential == null) {
            AzureKeyVaultService akvs = AzureKeyVaultService.GetInstance();

            // Retrieve Graph API configuration from Azure Key Vault
            char[] clientId = akvs.getSecret("Graph-ClientId");
            char[] clientSecret = akvs.getSecret("Graph-ClientSecret");
            char[] tenantId = akvs.getSecret("Graph-TenantId");
    
            if (clientId == null || clientSecret == null || tenantId == null) {
                throw new Exception("Error while retrieving SMTP server configuration from Azure Key Vault.");
            }
    
            _clientSecretCredential = new ClientSecretCredentialBuilder()
                .clientId(String.valueOf(clientId))
                .clientSecret(String.valueOf(clientSecret))
                .tenantId(String.valueOf(tenantId))
                .build();
        }

        if (_appClient == null) {
            _appClient = new GraphServiceClient(_clientSecretCredential, graphScopes);
        }

        final TokenRequestContext context = new TokenRequestContext();
        context.addScopes(graphScopes);

        final AccessToken token = _clientSecretCredential.getToken(context).block();
    }

    public static void AddLineToCsvFile(String file, String line) {
        try {

        } catch (Exception e) {
            throw e;
        }
    }
}
