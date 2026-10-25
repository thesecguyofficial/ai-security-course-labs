-- BigQuery, on the request-response logging table (one table per model config; change the name).
SELECT model,
       TIMESTAMP_TRUNC(logging_time, HOUR) AS hour,
       SUM(CAST(JSON_VALUE(full_response, '$.usageMetadata.totalTokenCount') AS INT64)) AS tokens,
       COUNT(*) AS calls
FROM `example-chatbot-prod.ai_logs.request_response_logging`
WHERE logging_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
GROUP BY model, hour
ORDER BY tokens DESC
