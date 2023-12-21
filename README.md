Code burp extension to do intruder file uploading
that contain 3 tabs
1. "Positions" tab that contain 2 main features
	1.1 choose an upload mode (upload one file per one request, upload all files in one request)
	1.2 set payload position (add, clear, auto, refresh selected position)
2. "Payloads" tab that contain 2 main features
	2.1 set payload (add files from your computer to the list, remove file from the list, clear all files in the list)
	2.2 preview request that will be sent after click 'start upload' (you can edit in each request manually)
3. "Upload history" that contain 2 main parts (like http history)
	3.1 list of request was sent that columns contain number of request, url, method, file path, status code, response length, time
	3.2 Request & response review


Features
1. Select your own files to upload.
2. Modify HTTP request as follow. 
	2.1 Editing HTTP request as your need.
	2.2 Adding file(s) into HTTP request.
	2.3 There 2 modes for files uploading that consist of 
		> 	upload single file per request.
		>	upload multiple files in a request.
	2.4 Supporting HTTP method POST, PUT and PATCH.
3. Preview HTTP request before send to the host.
4. Collect and preview upload history.
