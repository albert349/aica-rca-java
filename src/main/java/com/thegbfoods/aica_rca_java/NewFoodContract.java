package com.thegbfoods.aica_rca_java;

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
    private static final AzureKeyVaultService akvs = AzureKeyVaultService.GetInstance();
    private static EmailService emailService = null;

    /**
     * This function listens at endpoint "/api/NewFoodContract"
     */
    @FunctionName("NewFoodContract")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {
                    HttpMethod.POST
            }, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        //Ajout log de l envelop 20250220
        context.getLogger().info("Received request Body: " + request.getBody().orElse(""));
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
            context.getLogger().severe("unknown | Error: Couldn't find envelopeId.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("unknown | Error: Couldn't find envelopeId.")
                    .build();
        }

        // Retrieve sender email for email notification
        String emailSender = null;
        try {
            emailSender = jsonNode.get("data").get("envelopeSummary").get("sender").get("email").asText();
        } catch (Exception e) {
            context.getLogger().severe(envelopeId + " | Error: Couldn't find sender email.");
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body(envelopeId + " | Error: Couldn't find sender email.")
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

            // Check company_id
            if (companyId == null) {
                context.getLogger().severe(envelopeId + " | Error: Couldn't find company_id.");
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                        .body(envelopeId + " | Error: Couldn't find company_id.")
                        .build();
            }

            // Check producer_id
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

        // Create MultipartEntity
        HttpEntity multipartEntity = MultipartEntityBuilder.create()
                .setMode(HttpMultipartMode.BROWSER_COMPATIBLE)
                .addBinaryBody("files", tempFile, ContentType.DEFAULT_BINARY, tempFile.getName())
                .addTextBody("metadata", jsonPart, ContentType.APPLICATION_JSON)
                .build();

        // Get mode DEV or PRO
        String mode = System.getenv("mode");
        String apiUrl;

        if (mode == null || mode == "DEV") {
            // DEV url
            apiUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/servicioweb/nuevocontrato";
        } else {
            // PRO url
            apiUrl = "https://servicio.mapa.gob.es/wsregcontratosaica/servicioweb/nuevocontrato";
        }

        // Get OAuth2 token
        String authToken;
        try {
            authToken = getOAuthToken(context, envelopeId, companyId);
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

        // Send the request to the external API
        try {
            HttpPost postRequest = new HttpPost(apiUrl);
            postRequest.setEntity(multipartEntity);
            postRequest.setHeader("Authorization", "Bearer " + authToken);

            try (CloseableHttpResponse response = httpClient.execute(postRequest)) {
                if (emailService == null) {
                    emailService = EmailService.GetInstance();
                }
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                JsonNode responseJson = new ObjectMapper().readTree(responseBody);
                String status = null;
                String contractId = null;
                String errorCode = null;
                String errorDescription = null;
                String initialEmailSubject = "AICA RCA ";
                String initialEmailBody = "Envelope ID: " + envelopeId + "\n" +
                    "Enterprise ID: " + companyId + "\n" +
                    "Provider ID: " + producerId + "\n";

                if (statusCode == 200) {
                    // Success
                    status = responseJson.get("status").asText();
                    contractId = responseJson.get("contract_id").asText();
                    try {
                        emailService.sendEmail(emailSender, initialEmailSubject + "OK " + envelopeId, initialEmailBody +
                        "Status: " + status + "\n" +
                        "Contract ID: " + contractId + "\n");
                    } catch (Exception e) {
                        context.getLogger().severe(e.getMessage());
                    }
                    return request.createResponseBuilder(HttpStatus.valueOf(statusCode))
                        .body(responseBody)
                        .build();
                } else {
                    // Error
                    status = responseJson.get("status").asText();
                    errorCode = responseJson.get("error_code").asText();
                    errorDescription = responseJson.get("error_description").asText();
                    context.getLogger().severe(envelopeId + " | Failed to create new contract to AICA RCA."
                        + " | status = " + status + " | error_code = "+ errorCode + " | error_description = " + errorDescription);
                    try {
                        emailService.sendEmail(emailSender, initialEmailSubject + "ERROR " + envelopeId, initialEmailBody +
                        "Status: " + status + "\n" +
                        "Error Code: " + errorCode + "\n" +
                        "Error Description: " + errorDescription);
                    } catch (Exception e) {
                        context.getLogger().severe(e.getMessage());
                    }
                    return request.createResponseBuilder(HttpStatus.valueOf(statusCode))
                        .body(responseBody)
                        .build();
                }
            }
        } catch (Exception e) {
            try {
                emailService.sendEmail(emailSender, "AICA RCA EXCEPTION " + envelopeId, envelopeId + " | Error: Failed to send POST request for NewFoodContract: " + e.getMessage());
            } catch (Exception ex) {
                context.getLogger().severe(ex.getMessage());
            }
            context.getLogger().severe(envelopeId + " | Error: Failed to send POST request for NewFoodContract: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(envelopeId + " | Error: Failed to send POST request for NewFoodContract: " + e.getMessage())
                    .build();
        }
    }

    private String getOAuthToken(ExecutionContext context, String envelopeId, String companyId) throws Exception {
        lock.lock();
        try {
            // Check if token is still valid
            if (oauthToken != null && Instant.now().isBefore(tokenExpiryTime)) {
                return oauthToken;
            }

            // Retrieve ClientId and ClientSecret from Azure Key Vault in DEV or PRD
            String mode = System.getenv("mode");
            String tokenUrl;
            String clientIdName;
            String clientSecretName;

            if (mode == null || mode.equals("DEV")) {
                clientIdName = "DEV-AICA-CLIENT-ID" + companyId; //20250218
                clientSecretName = "DEV-AICA-CLIENT-SECRET" + companyId; //20250218;
                tokenUrl = "https://integra-servicio.mapa.gob.es/wsregcontratosaica/oauth/token";
            } else {
                clientIdName = "PRO-AICA-CLIENT-ID" + companyId; //20250218;
                clientSecretName = "PRO-AICA-CLIENT-SECRET" + companyId; //20250218;
                tokenUrl = "https://servicio.mapa.gob.es/wsregcontratosaica/oauth/token";
            }

            char[] clientId = null;
            char[] clientSecret = null;
            try {
                clientId = akvs.getSecret(clientIdName);
                clientSecret = akvs.getSecret(clientSecretName);

                if (clientId == null || clientSecret == null) {
                    throw new Exception(clientIdName + " or " + clientSecretName + " is null.");
                }
            } catch (Exception e) {
                context.getLogger().severe("Error while retrieving Azure Key Vault secrets: " + e.getMessage());
                throw new Exception("Error while retrieving Azure Key Vault secrets: " + e.getMessage());
            }

            // Request new token
            Long expiresIn = null;

            HttpPost tokenRequest = new HttpPost(tokenUrl);
            tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
            tokenRequest.setEntity(new StringEntity("grant_type=client_credentials&client_id=" + String.valueOf(clientId)
                + "&client_secret=" + String.valueOf(clientSecret)));

            try (CloseableHttpResponse response = httpClient.execute(tokenRequest)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    throw new RuntimeException("Failed to get OAuth2 token with statusCode = " + statusCode);
                }

                String responseBody = EntityUtils.toString(response.getEntity());
                JsonNode responseJson = new ObjectMapper().readTree(responseBody);
                oauthToken = responseJson.get("access_token").asText();
                expiresIn = responseJson.get("expires_in").asLong();
                tokenExpiryTime = Instant.now().plusSeconds(expiresIn).minusSeconds(60);

                return oauthToken;
            } catch (Exception e) {
                context.getLogger().severe("Failed to send POST request for OAuth2 token: " + e.getMessage());
                throw new Exception("Failed to send POST request for OAuth2 token: " + e.getMessage());
            }
        } finally {
            lock.unlock();
        }
    }
}