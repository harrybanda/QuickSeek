import json
import boto3

BUCKET = 'quickseek'

transcribe = boto3.client("transcribe")

def handler(event, context):
    v_name = event["pathParameters"]["video-name"]
    
    response = transcribe.start_transcription_job(
        TranscriptionJobName = v_name,
        LanguageCode = "en-US",
        MediaFormat = "mp4",
        Media={
            "MediaFileUri": "https://s3-us-east-1.amazonaws.com/" + BUCKET + "/" + v_name + ".mp4"
        },
        OutputBucketName = BUCKET,
    )
    
    message = {"name": v_name}

    return {
        "statusCode": 200,
        "body": json.dumps(message),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        }
    }