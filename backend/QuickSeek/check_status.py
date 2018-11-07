import json
import boto3

transcribe = boto3.client("transcribe")

def handler(event, context):
    job_name = event["pathParameters"]["job-name"]
    
    response = transcribe.get_transcription_job(TranscriptionJobName = job_name)
    message = response["TranscriptionJob"]["TranscriptionJobStatus"]

    return {
        "statusCode": 200,
        "body": json.dumps({"status": message}),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        }
    }