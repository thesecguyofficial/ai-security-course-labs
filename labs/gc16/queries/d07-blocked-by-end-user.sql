-- BigQuery, on the request-response logging table. Needs labels.end_user set by your backend on every request.
SELECT JSON_VALUE(full_request, '$.labels.end_user') AS end_user,
       TIMESTAMP_BUCKET(logging_time, INTERVAL 10 MINUTE) AS window_start,
       COUNT(*) AS blocked
FROM `example-chatbot-prod.ai_logs.request_response_logging`
WHERE JSON_VALUE(full_response, '$.promptFeedback.blockReason') = 'MODEL_ARMOR'
GROUP BY end_user, window_start
HAVING blocked >= 3
ORDER BY window_start
