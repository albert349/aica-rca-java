package com.thegbfoods.aica_rca_java;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

private void WriteLogsToFile(ExecutionContext context, String logMessage) {
    String logFileName = "log_" + System.currentTTimeMillis() + ".csv";
    File logFile = new File(System.getProperty("java.io.tmdir"), logFileName);

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true))) {
        writer.write(logMessage);
        writer.newline();
        context.getLogger().info("Log written to file: " + logFile.getAbsolutePath());
    } catch (IOException e) {
        context.getLogger().severe("Failed to write logs to file: " + e.getMessage());
    }
}
