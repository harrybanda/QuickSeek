import json
import boto3
from pytube import YouTube
import botocore.vendored.requests.packages.urllib3 as urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s3 = boto3.client("s3")

def handler(event, context):
    v_id = event["pathParameters"]["video-id"]
    yt_url = "https://www.youtube.com/watch?v=" + v_id
    
    yt = YouTube(yt_url)
    stream = yt.streams.filter(progressive=True, file_extension="mp4").all()[-1]
    
    bucket = "quickseek"
    key = v_id + ".mp4"
    
    http = urllib3.PoolManager()
    s3.upload_fileobj(http.request("GET", stream.url, preload_content = False), bucket, key)
    
    message = {
        "id": v_id,
        "title": yt.title,
        "resolution": stream.resolution,
        "mime_type": stream.mime_type
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(message),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        }
    }