package com.thegbfoods.aica_rca_java;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
                    HttpMethod.POST }, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
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
                    .body("Invalid JSON format.")
                    .build();
        }

        // Validate JSON parameters
        if (!jsonNode.has("file_content") || !jsonNode.has("file_name") || !jsonNode.has("company_id")
                || !jsonNode.has("producer_id")) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Missing required parameters.")
                    .build();
        }

        // Extract parameters
        String fileContentBase64 = jsonNode.get("file_content").asText();
        String fileName = jsonNode.get("file_name").asText();
        String companyId = jsonNode.get("company_id").asText();
        String producerId = jsonNode.get("producer_id").asText();

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
                    .body("Error processing file.")
                    .build();
        }

        // Create JSON for company_id and producer_id
        String jsonPart;
        try {
            // ObjectNode jsonObject = mapper.createObjectNode();
            // jsonObject.put("company_id", companyId);
            // jsonObject.put("producer_id", producerId);
            // jsonPart = mapper.writeValueAsString(jsonObject);
            jsonPart = mapper.createObjectNode()
                    .put("company_id", companyId)
                    .put("producer_id", producerId)
                    .toString();
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error creating JSON part.")
                    .build();
        }

        // Get OAuth2 token
        String apiUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/servicioweb/nuevocontrato";
        String authToken;
        try {
            authToken = getOAuthToken(context);
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error obtaining OAuth2 token: " + e.getMessage())
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
                    .body("Error sending POST request: " + e.getMessage())
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

            // Request new token
            String tokenUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/oauth/token";
            String clientId = "3NWT3I";
            String clientSecret = "b72q:0v2B1bZe.xd";
            String tokenRequestPayload = "grant_type=client_credentials&client_id=" + clientId + "&client_secret="
                    + clientSecret;
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
