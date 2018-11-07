import json
import boto3

s3 = boto3.client('s3')
comprehend = boto3.client('comprehend')

def utf8len(s):
    return len(s.encode('utf-8'))

def truncateUTF8length(unicodeStr, maxsize):
    return str(unicodeStr.encode("utf-8")[:maxsize], "utf-8", errors="ignore")
            
def handler(event, context):
    j_name = event["pathParameters"]["json-name"]
    
    bucket = 'quickseek'
    json_file_name = j_name + ".json"
    json_object = s3.get_object(Bucket = bucket, Key = json_file_name)
    json_file_reader = json_object['Body'].read()
    json_data = json.loads(json_file_reader)
    final_json = json_data["results"]["items"]
    transcript = json_data["results"]["transcripts"][0]["transcript"]
    transcript_length = utf8len(transcript);
    
    if (transcript_length > 5000):
        transcript = truncateUTF8length(transcript, 5000)
        
    sentiment = comprehend.detect_sentiment(Text=transcript, LanguageCode='en')

    message = {
        "json": final_json,
        "sentiment": sentiment
    }

    #s3.delete_object(Bucket=bucket, Key=j_name+".mp4")
    #s3.delete_object(Bucket=bucket, Key=job_name+".json")
    #transcribe.delete_transcription_job(TranscriptionJobName=job_name)
        
    return {
        "statusCode": 200,
        "body": json.dumps(message),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        }
    }