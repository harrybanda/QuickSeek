# QuickSeek
QuickSeek is a chrome extension that allows you to easily search and navigate through a YouTube video, you can quickly find and watch only parts of the video that contain words you are looking for. The Chrome extension uses Amazon Transcribe to make the audio searchable and Amazon Comprehend to perform sentiment analysis on the transcript.

#Backend setup
1. Go to https://aws.amazon.com/lambda/
2. Create 4 lambda functions:
   - download_to_s3
   - get_transcripts
   - transcribe_audio
   - check_status
3. Copy the code from the repostroy to each of the lambda functions created

4. install boto3: https://github.com/boto/boto3
5. install pytube: https://github.com/nficano/pytube
6. install urlib3: https://pypi.org/project/urllib3/
7. create an S3 bucket called quickseek
