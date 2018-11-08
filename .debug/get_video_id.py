import json
from pytube import YouTube

def handler(event, context):
    v_id = event["pathParameters"]["video-id"]
    yt_url = "https://www.youtube.com/watch?v=" + v_id
    
    yt = YouTube(yt_url)
    stream = yt.streams.filter(only_audio=True, file_extension="mp4").all()[0]
    
    message = {
        "id": v_id,
        "title": yt.title,
        "mime_type": stream.mime_type,
        "url": stream.url
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(message),
        "headers": {
            "Access-Control-Allow-Origin": "chrome-extension://oonbcmjehmjoihomblgododljmcphcki",
            "Content-Type": "application/json"
        }
    }