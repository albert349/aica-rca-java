package com.thegbfoods.aica_rca_java;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

public class AzureKeyVaultService {
    private static String _keyVaultUri;
    private static AzureKeyVaultService _instance;
    private final SecretClient _secretClient;

    private AzureKeyVaultService() {
        try {
            String mode = System.getenv("mode");

            if (mode == null || mode == "DEV") {
                _keyVaultUri = "https://kv-docusign-integration.vault.azure.net";
            } else {
                _keyVaultUri = "https://kv-docusign-int-pro.vault.azure.net/";
            }
            _secretClient = new SecretClientBuilder()
                .vaultUrl(_keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
        } catch (Exception e) {
            throw e;
        }
    }

    public static AzureKeyVaultService GetInstance() {
        if (_instance == null) {
            synchronized (AzureKeyVaultService.class) {
                if (_instance == null) {
                    try {
                        _instance = new AzureKeyVaultService();
                    } catch (Exception e) {
                        throw e;
                    }
                }
            }
        }
        return _instance;
    }

    // Retrieve a secret value
    public char[] getSecret(String secretName) {
        try {
            return _secretClient.getSecret(secretName).getValue().toCharArray();
        } catch (Exception e) {
            return null;
        }
    }
}
