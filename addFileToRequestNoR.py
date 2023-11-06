import os
import re
import subprocess
import json
import requests
import tempfile
import magic # pip install python-magic-bin

requestFilePath = "request.txt"
fileUpload = "Files_Test/file.png" # For now support image, audio, video, and PDF metadata only
outputPath = "output_file.bin"
fileUploadList = ["Files_Test/file.png", "Files_Test/s_file.pdf", "Files_Test/s_file.docx"]
ModeFlag = 1 # ModeFlag = 0 (not set), 1 (a file per request), 2 (all files in a request)
BoundaryFlag = 0 # BoundaryFlag = 0 (no boundary), 1 (have boundary)




# REQUEST #################
def read_request(requestFilePath):
    with open(requestFilePath, 'rb') as file:
        data = file.read()
        file.close()
        return data # Binary

def get_http_method(requestFilePath):
    with open(requestFilePath, 'rb') as f:
        first_line = f.readline()
        match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s', first_line.decode('utf-8')) # \s matches any whitespace character, including tabs.
        if match:
            return match.group(1) # utf-8
        else:
            print("HTTP Method not found!")

def get_boundary(requestFilePath):
    global BoundaryFlag, ModeFlag
    content = read_request(requestFilePath)

    # Regular expression to find the boundary value (adapted for bytes)
    match = re.search(b'boundary=(.+?)\n', content)
    
    if match:
        boundary_value = match.group(1)
        # print("boundary=", boundary_value.decode('utf-8', 'ignore'))
        BoundaryFlag = 1
        return boundary_value # binary
    else:
        print("Have no boundary")
        BoundaryFlag = 0
        ModeFlag = 1
        return None

def add_new_part(boundary, new_filename, new_content_type, new_binary_content):
    return boundary + b'\n' + \
           b'Content-Disposition: form-data; name="file"; filename=' + new_filename + b'\n' + \
           b'Content-Type: ' + new_content_type + b'\n\n' + \
           new_binary_content + b'\n'

def edit_part(part, new_filename, new_content_type, new_binary_content):
    # Use regular expressions to identify and replace the filename and Content-Type
    part = re.sub(b'(filename=")[^"]*(")', b'\\1' + new_filename + b'\\2', part)
    
    # Check if the Content-Type is present and replace it, otherwise add it
    if b'Content-Type:' in part:
        part = re.sub(b'(Content-Type: )[^\n]*', b'\\1' + new_content_type, part)
    else:
        position = part.find(b'\n\n')
        part = part[:position] + b'\nContent-Type: ' + new_content_type + part[position:]
    
    # Find the start position of old binary content
    position = part.find(b'\n\n') + 4
        # Find the end position of old binary content. If we're assuming that the old binary content ends 
        # just before the next boundary or the end of the part, we can use the end of the part as the position.
    end_position = len(part)

    # Replace the old content with new_binary_content
    part = part[:position] + new_binary_content + b'\n' + part[end_position:]
    
    return part



# FILE UPLOAD #################       
def get_mime_type(filename):
    mime = magic.Magic(mime=True)
    return (mime.from_file(filename)).encode()

def get_content_length(filename):
    with open(filename, 'rb') as file:
        data = file.read()
        content_length = len(data)
        return content_length.encode()

def get_filename(filename):
    return (os.path.basename(filename)).encode()

def read_file_upload(fileUpload):
    with open(fileUpload, 'rb') as file:
        data = file.read()
        file.close()
        return data # Binary



# MAIN METHOD #################
def save_binary_file(new_filename, content):
    with open(new_filename, "wb") as f:
        f.write(content)
        f.close()
    print(f"Message saved to {new_filename}")

def generate_request(url, method, fileUpload):
    with open(fileUpload, 'rb') as file:
        files = {'file': file}
        # Using the 'request' function of the requests library to send a request with any method
        response = requests.request(method.upper(), url, files=files)
    return response

def post_bound(request, boundary, fileUploadList):
    global ModeFlag
    start_boundary = b'--' + boundary
    end_boundary = start_boundary + b'--'
    # Special character for separation, for example, a newline
    separator = b'\n--*--\n-*-*-\n-*-\n------*------\n-*-\n-*-*-\n--*--\n'

    if ModeFlag == 1:
        for index, file in enumerate(fileUploadList):
            # Extract the data between \n\n and the ending sequence
            start_index = request.find(b'\n\n')
            end_index = request.find(end_boundary)
            extracted_data = request[start_index+4:end_index]

            # Split the extracted data using the specified delimiter
            parts = extracted_data.split(start_boundary)[1:]
            
            # Extract parts and edit (just edit some part containing "filename=<filename>")
            new_filename = get_filename(file)
            new_file_mime = get_mime_type(file)
            new_file_content = read_file_upload(file)

            edited = False # To keep track if any part was edited
            already_edited = False  # To monitor if we've edited a "filename=" part
            # Create a temporary file to store edited parts
            with tempfile.TemporaryFile() as temp_file:
                for part in parts:
                    if b'filename=' in part and not already_edited:
                        edited_part = edit_part(part, new_filename, new_file_mime, new_file_content)
                        temp_file.write(start_boundary + edited_part)
                        already_edited = True
                        edited = True
                    else:
                        temp_file.write(start_boundary + part)

                # Check if no part was edited, then append the new part before the footer
                if not edited:
                    new_part = add_new_part(start_boundary, new_filename, new_file_mime, new_file_content)
                    temp_file.write(new_part)

                # Move file pointer to start of the temp_file
                temp_file.seek(0)

                # Construct final_message
                header = request[:start_index+4]
                edited_data = temp_file.read()
                footer = start_boundary + b'--\n'
                final_message = header + edited_data + footer

                # Save the modified data to a new binary file
                if index == 0:
                    with open('output_file.bin', 'wb') as f:
                        f.write(final_message + separator)
                        print(f"File number {index} was edited")
                else:
                    with open('output_file.bin', 'ab') as f:
                        f.write(final_message + separator)
                        print(f"File number {index} was edited")
    
    elif ModeFlag==2:
        for index, file in fileUploadList:
            pass

def change_file(requestFilePath, fileUploadList):
    if get_http_method(requestFilePath) == 'POST':
        # Original request
        request = read_request(requestFilePath)
        boundary = get_boundary(requestFilePath)
        if boundary:
            post_bound(request, boundary, fileUploadList)
            print(">>> Modify requst successful <<<")
        else:
            pass

    elif get_http_method(requestFilePath) == 'PUT':
        pass

    elif get_http_method(requestFilePath) == 'PATCH':
        pass

    else:
        pass



change_file(requestFilePath, fileUploadList)
