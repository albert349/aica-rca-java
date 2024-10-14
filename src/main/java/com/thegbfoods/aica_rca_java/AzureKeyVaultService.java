package com.thegbfoods.aica_rca_java;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

public class AzureKeyVaultService {
    private final static String keyVaultUri = "https://kv-docusign-integration.vault.azure.net";
    private static AzureKeyVaultService instance;
    private final SecretClient secretClient;

    public AzureKeyVaultService() {
        try {
            secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
        } catch (Exception e) {
            throw e;
        }
    }

    public static AzureKeyVaultService getInstance() {
        if (instance == null) {
            synchronized (AzureKeyVaultService.class) {
                if (instance == null) {
                    try {
                        instance = new AzureKeyVaultService();
                    } catch (Exception e) {
                        throw e;
                    }
                }
            }
        }
        return instance;
    }

    // Retrieve a secret value
    public char[] getSecret(String secretName) {
        try {
            return secretClient.getSecret(secretName).getValue().toCharArray();
        } catch (Exception e) {
            return null;
        }
    }
}
