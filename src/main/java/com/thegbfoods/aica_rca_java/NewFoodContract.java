package com.thegbfoods.aica_rca_java;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.io.File;
import java.io.FileOutputStream;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

/**
 * Azure Functions with HTTP Trigger.
 */
public class NewFoodContract {
    private static String oauthToken = null;
    private static Instant tokenExpiryTime = Instant.now();
    private static final ReentrantLock lock = new ReentrantLock();
    private static final CloseableHttpClient httpClient = HttpClients.createDefault();

    /**
     * This function listens at endpoint "/api/NewFoodContract"
     */
    @FunctionName("NewFoodContract")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {
                    HttpMethod.POST
            }, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse the request body
        String requestBody = request.getBody().orElse("");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;

        try {
            jsonNode = mapper.readTree(requestBody);
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Error: Failed to read JSON input")
                    .build();
        }

        // Retrieve company_id and producer_id
        String companyId = null;
        String producerId = null;
        try {
            JsonNode textCustomFields = jsonNode.get("data").get("envelopeSummary").get("customFields")
                    .get("textCustomFields");
            if (textCustomFields.isArray()) {
                for (JsonNode envelopeDocument : (ArrayNode) textCustomFields) {
                    if (envelopeDocument.path("name").asText().equals("company ID")) {
                        companyId = envelopeDocument.get("value").asText();
                    } else if (envelopeDocument.path("name").asText().equals("producer ID")) {
                        producerId = envelopeDocument.get("value").asText();
                    }
                }
            }
            if (companyId == null) {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body("Error: Couldn't find company_id.")
                        .build();
            }
            if (producerId == null) {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body("Error: Couldn't find producer_id.")
                        .build();
            }
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Error: Failed to parse text custom fields.")
                    .build();
        }

        // Retrieve contract content and name
        String fileContentBase64 = null;
        String fileName = null;
        try {
            JsonNode envelopeDocuments = jsonNode.get("data").get("envelopeSummary").path("envelopeDocuments");

            if (envelopeDocuments.isArray()) {
                for (JsonNode envelopeDocument : (ArrayNode) envelopeDocuments) {
                    if (!envelopeDocument.path("documentId").asText().equals("certificate")) {
                        fileContentBase64 = envelopeDocument.get("PDFBytes").asText();
                        fileName = envelopeDocument.get("name").asText();
                    }
                }
            }
            if (fileContentBase64 == null) {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body("Error: Couldn't find contract.")
                        .build();
            }
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Error: Failed to parse envelope documents.")
                    .build();
        }

        // Convert Base64 file to a temporary file
        File tempFile;
        try {
            byte[] fileBytes = Base64.getDecoder().decode(fileContentBase64);
            tempFile = File.createTempFile(fileName, "");
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(fileBytes);
            }
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: Failed to process contract.")
                    .build();
        }

        // Create JSON for company_id and producer_id
        String jsonPart;
        try {
            jsonPart = mapper.createObjectNode()
                    .put("company_id", companyId)
                    .put("producer_id", producerId)
                    .toString();
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: Failed to create JSON for company_id and producer_id.")
                    .build();
        }

        // Get OAuth2 token
        String apiUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/servicioweb/nuevocontrato";
        String authToken;
        try {
            authToken = getOAuthToken(context);
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: Failed to obtain OAuth2 token: " + e.getMessage())
                    .build();
        }

        // Create MultipartEntity
        HttpEntity multipartEntity = MultipartEntityBuilder.create()
                .setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addBinaryBody("files", tempFile, ContentType.DEFAULT_BINARY, tempFile.getName())
                .addTextBody("metadata", jsonPart, ContentType.APPLICATION_JSON)
                .build();

        // Send the request to the external API
        try {
            HttpPost postRequest = new HttpPost(apiUrl);
            postRequest.setEntity(multipartEntity);
            postRequest.setHeader("Authorization", "Bearer " + authToken);

            try (CloseableHttpResponse response = httpClient.execute(postRequest)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                int statusCode = response.getStatusLine().getStatusCode();

                return request.createResponseBuilder(HttpStatus.valueOf(statusCode))
                        .body(responseBody)
                        .build();
            }
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: Failed to send POST request: " + e.getMessage())
                    .build();
        }
    }

    private String getOAuthToken(ExecutionContext context) throws Exception {
        lock.lock();
        try {
            // Check if token is still valid
            if (oauthToken != null && Instant.now().isBefore(tokenExpiryTime)) {
                return oauthToken;
            }

            // Retrieve ClientId and ClientSecret from Azure Key Vault in DEV or PRD
            String keyVaultUri = "https://kv-docusign-integration.vault.azure.net";
            String kvsPrefix;
            String mode = System.getProperty("mode");

            if (mode == null || mode.equals("debug")) {
                kvsPrefix = "DEV";
            } else {
                kvsPrefix = "PRD";
            }

            String clientId = "3NWT3I";
            String clientSecret = "b72q:0v2B1bZe.xd";
            try {
                SecretClient secretClient = new SecretClientBuilder()
                        .vaultUrl(keyVaultUri)
                        .credential(new DefaultAzureCredentialBuilder().build())
                        .buildClient();
                KeyVaultSecret kvsClientId = secretClient.getSecret(kvsPrefix + "-AICA-CLIENT-ID");
                KeyVaultSecret kvsClientSecret = secretClient.getSecret(kvsPrefix + "DEV-AICA-CLIENT-ID");
                clientId = kvsClientId.getValue();
                clientSecret = kvsClientSecret.getValue();
            } catch (Exception e) {
                // throw new Exception("Error while retrieving Azure Key Vault secrets");
            }

            // Request new token
            String tokenUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/oauth/token";
            String tokenRequestPayload = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" +
                    clientSecret;
            Long expiresIn = null;

            HttpPost tokenRequest = new HttpPost(tokenUrl);
            tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
            tokenRequest.setEntity(new StringEntity(tokenRequestPayload));

            try (CloseableHttpResponse response = httpClient.execute(tokenRequest)) {
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new RuntimeException("Failed to get OAuth token");
                }

                String responseBody = EntityUtils.toString(response.getEntity());
                JsonNode responseJson = new ObjectMapper().readTree(responseBody);
                oauthToken = responseJson.get("access_token").asText();
                expiresIn = responseJson.get("expires_in").asLong();
                tokenExpiryTime = Instant.now().plusSeconds(expiresIn).minusSeconds(60);

                return oauthToken;
            }
        } finally {
            lock.unlock();
        }
    }
}