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
        // Parse the request body
        String requestBody = request.getBody().orElse("");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(requestBody);
        } catch (Exception e) {
            context.getLogger().severe("Error: Failed to read JSON input");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Error: Failed to read JSON input")
                    .build();
        }

        // Retrieve envelopeId
        String envelopeId = null;
        try {
            envelopeId = jsonNode.get("data").get("envelopeId").asText();
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Couldn't find envelopeId.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body(envelopeId + " | Error: Couldn't find envelopeId.")
                    .build();
        }

        // Return 204 if envelope is not completed
        try {
            JsonNode event = jsonNode.get("event");
            if (event == null || event.isNull() || !event.asText().equals("envelope-completed")) {
                context.getLogger().fine(envelopeId + " | Envelope is not completed.");
                return request.createResponseBuilder(HttpStatus.NO_CONTENT)
                        .build();
            }
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Failed to parse event.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body(envelopeId + " | Error: Failed to parse event.")
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
                    if (envelopeDocument.path("name").asText().equals("Enterprise ID")) {
                        companyId = envelopeDocument.get("value").asText();
                    } else if (envelopeDocument.path("name").asText().equals("Provider ID")) {
                        producerId = envelopeDocument.get("value").asText();
                    }
                }
            }

            if (companyId == null) {
                context.getLogger().severe(envelopeId + " | Error: Couldn't find company_id.");
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body(envelopeId + " | Error: Couldn't find company_id.")
                        .build();
            }
            if (producerId == null) {
                context.getLogger().severe(envelopeId + " | Error: Couldn't find producer_id.");
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body(envelopeId + " | Error: Couldn't find producer_id.")
                        .build();
            }
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Failed to parse text custom fields.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body(envelopeId + " | Error: Failed to parse text custom fields.")
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
                context.getLogger().severe(envelopeId + " | Error: Failed to parse envelope documents.");
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body(envelopeId + " | Error: Couldn't find contract.")
                        .build();
            }
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Failed to parse envelope documents.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body(envelopeId + " | Error: Failed to parse envelope documents.")
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
            context.getLogger().severe(envelopeId + " | Error: Failed to process contract.");
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to process contract.")
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
            context.getLogger().severe(envelopeId + " | Error: Failed to create JSON for company_id and producer_id.");
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to create JSON for company_id and producer_id.")
                    .build();
        }

        // Get OAuth2 token
        String apiUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/servicioweb/nuevocontrato";
        String authToken;
        try {
            authToken = getOAuthToken(context, envelopeId);
            if (authToken == null) {
                context.getLogger().severe(envelopeId + " | Error: Failed to obtain OAuth2 token.");
                return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to obtain OAuth2 token.")
                    .build();
        }
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Failed to obtain OAuth2 token: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to obtain OAuth2 token: " + e.getMessage())
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

                // Return success
                context.getLogger().info(envelopeId + " | Successfully created new contract to AICA RCA.");
                return request.createResponseBuilder(HttpStatus.valueOf(statusCode))
                        .body(responseBody)
                        .build();
            }
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Failed to send POST request: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to send POST request: " + e.getMessage())
                    .build();
        }
    }

    private String getOAuthToken(ExecutionContext context, String envelopeId) throws Exception {
        lock.lock();
        try {
            // Check if token is still valid
            if (oauthToken != null && Instant.now().isBefore(tokenExpiryTime)) {
                return oauthToken;
            }

            // Retrieve ClientId and ClientSecret from Azure Key Vault in DEV or PRD
            String keyVaultUri = "https://kv-docusign-integration.vault.azure.net";
            String kvsPrefix;
            String mode = System.getenv("mode");

            if (mode == null || mode.equals("DEV")) {
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
                KeyVaultSecret kvsClientSecret = secretClient.getSecret(kvsPrefix + "-AICA-CLIENT-SECRET");
                clientId = kvsClientId.getValue();
                clientSecret = kvsClientSecret.getValue();
            } catch (Exception e) {
                context.getLogger().severe(envelopeId + " | Error while retrieving Azure Key Vault secrets: " + e.getMessage())
                throw new Exception(envelopeId + " | Error while retrieving Azure Key Vault secrets: " + e.getMessage());
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
            } catch (Exception e) {
                context.getLogger().severe(envelopeId + " | Error while executing request for Azure Key Vault secrets: " + e.getMessage());
                throw new Exception(envelopeId + " | Error while executing request for Azure Key Vault secrets: " + e.getMessage());
            }
        } finally {
            lock.unlock();
        }
    }
}