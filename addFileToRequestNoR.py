import os
import re
import tempfile
import mimetypes

requestFilePath = "request.txt"
fileUpload = "Files_Test/file.png" # For now support image, audio, video, and PDF metadata only
outputPath = "output_file.bin"
fileUploadList = ["Files_Test/file.json", "Files_Test/file.png","Files_Test/s_file.pdf", "Files_Test/s_file.docx"]
ModeFlag = 2 # ModeFlag = 0 (not set), 1 (a file per request), 2 (all files in a request)
# BoundaryFlag = 0 # BoundaryFlag = 0 (no boundary), 1 (have boundary)
# Special character for separation, for example, a newline
separator = b'\n--*--\n-*-*-\n-*-BurpExtensionByFolk44-*-\n-*-*-\n--*--\n'
modifiedFilename = "output_file.bin"



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
            return None

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
    position = part.find(b'\n\n') + 2
        # Find the end position of old binary content. If we're assuming that the old binary content ends 
        # just before the next boundary or the end of the part, we can use the end of the part as the position.
    end_position = len(part)

    # Replace the old content with new_binary_content
    part = part[:position] + new_binary_content + b'\n' + part[end_position:]
    
    return part



# FILE UPLOAD #################       
def get_mime_type(filename):
    return str(list(mimetypes.guess_type(filename))[0]).encode()

def get_content_length(filename):
    return str(os.path.getsize(filename)).encode()

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

def save_request_mode1(filename, index, message):
    global separator
    if index == 0:
        with open(filename, 'wb') as f:
            f.write(message + separator)
            print(f"File number {index} was added")
    else:
        with open(filename, 'ab') as f:
            f.write(message + separator)
            print(f"File number {index} was added")

def save_request_mode2(filename, message):
    # Save the modified data to a new binary file
    with open(filename, 'wb') as f:
        f.write(message)

def change_header_filename(part, method, new_filename):
    # Regex to match the pattern
    pattern = method + rb' (.*/).* (.+\n)'
    part = re.sub(pattern, method + rb' \1' + new_filename + rb' \2', part)
    return part

def change_content_type(part, file):
    # Replace or add Content-Type
    if b"Content-Type:" in part:
        part = re.sub(rb"Content-Type: .+?(?=;|\n)", b"Content-Type: " + get_mime_type(file), part)
    else:
        part += b"Content-Type: {}\n".format(get_mime_type(file))
    return part

def change_content_length(part, length=0, file=None):
    # Replace or add Content-Length
    if file is not None:
        if b"Content-Length:" in part:
            part = re.sub(rb"Content-Length: \d+", b"Content-Length: " + get_content_length(file), part)
        else:
            part += b"Content-Length: " + get_content_length(file) + b'\n'
    else:
        if b"Content-Length:" in part:
            part = re.sub(rb"Content-Length: \d+", b"Content-Length: " + (str(length).encode()), part)
        else:
            part = part + b"Content-Length: " + (str(length).encode()) + b'\n'
    return part



# Modifier #################
def post_bound(request, boundary, fileUploadList):
    global ModeFlag, separator
    start_boundary = b'--' + boundary
    end_boundary = start_boundary + b'--'

    # >>> One file per request <<<
    if ModeFlag == 1:
        for index, file in enumerate(fileUploadList):
            # Extract the data between \n\n and the ending sequence
            start_index = request.find(b'\n\n')
            end_index = request.find(end_boundary)
            extracted_data = request[start_index+2:end_index]

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
                header = request[:start_index+1]
                edited_data = temp_file.read()
                footer = start_boundary + b'--\n'
                body = edited_data + footer
                final_message = header + b'\n' + body

                # Save the modified data to a new binary file
                save_request_mode1(modifiedFilename, index, final_message)
    
    # >>> All files in a request <<<
    elif ModeFlag==2:
        fileIndex = 0
        # Extract the data between \n\n and the ending sequence
        start_index = request.find(b'\n\n')
        end_index = request.find(end_boundary)
        extracted_data = request[start_index+2:end_index]

        # Split the extracted data using the specified delimiter
        parts = extracted_data.split(start_boundary)[1:]
        
        edited = False
        with tempfile.TemporaryFile() as temp_file:
            for part in parts:
                if fileUploadList[fileIndex]:
                    # Extract parts and edit (just edit some part containing "filename=<filename>")
                    new_filename = get_filename(fileUploadList[fileIndex])
                    new_file_mime = get_mime_type(fileUploadList[fileIndex])
                    new_file_content = read_file_upload(fileUploadList[fileIndex])
                    if b'filename=' in part:
                        edited_part = edit_part(part, new_filename, new_file_mime, new_file_content)
                        temp_file.write(start_boundary + edited_part)
                        edited = True
                        fileIndex += 1
                    else:
                        temp_file.write(start_boundary + part)

            # Check if no part was edited, then append the new part before the footer
            while fileIndex < len(fileUploadList):# Extract parts and edit (just edit some part containing "filename=<filename>")
                new_filename = get_filename(fileUploadList[fileIndex])
                new_file_mime = get_mime_type(fileUploadList[fileIndex])
                new_file_content = read_file_upload(fileUploadList[fileIndex])

                new_part = add_new_part(start_boundary, new_filename, new_file_mime, new_file_content)
                temp_file.write(new_part)
                fileIndex += 1

            # Move file pointer to start of the temp_file
            temp_file.seek(0)

            # Construct final_message
            header = request[:start_index+2]
            edited_data = temp_file.read()
            footer = start_boundary + b'--\n'
            final_message = header + edited_data + footer

            # Save the modified data to a new binary file
            save_request_mode2(modifiedFilename, final_message)
    
    else:
        print("Not support this mode")

def post_unbound(request, fileUploadList):
    for index, file in enumerate(fileUploadList):
        # Extract parts between \n\n and the ending sequence
        header, body = request.split(b'\n\n', 1)
        header+= b'\n'
        
        # Replace or add Content-Type
        header = change_content_type(header, file)

        # Replace or add Content-Length
        header = change_content_length(header, file=file)
  
        # Extract parts and edit (just edit some part containing "filename=<filename>")
        body = read_file_upload(file)
        final_message = header + b"\n" + body

        # Save the modified data to a new binary file
        save_request_mode1(modifiedFilename, index, final_message)

def put(request, fileUploadList):
    for index, file in enumerate(fileUploadList):
        # Extract parts between \n\n and the ending sequence
        header, body = request.split(b'\n\n', 1)
        header+= b'\n'

        # Replace or add filename
        header = change_header_filename(header, b"PUT", get_filename(file))

        # Replace or add Content-Type
        header = change_content_type(header, file)

        # Replace or add Content-Length
        header = change_content_length(header, file=file)
  
        # Extract parts and edit (just edit some part containing "filename=<filename>")
        body = read_file_upload(file)
        final_message = header + b"\n" + body

        # Save the modified data to a new binary file
        save_request_mode1(modifiedFilename, index, final_message)

def patch_bound(request, boundary, fileUploadList):
    global ModeFlag, separator
    start_boundary = b'--' + boundary
    end_boundary = start_boundary + b'--'

    # >>> One file per request <<<
    if ModeFlag == 1:
        for index, file in enumerate(fileUploadList):
            # Extract the data between \n\n and the ending sequence
            start_index = request.find(b'\n\n')
            end_index = request.find(end_boundary)
            extracted_data = request[start_index+2:end_index]

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
                header = request[:start_index+1]
                edited_data = temp_file.read()
                footer = start_boundary + b'--\n'
                body = edited_data + footer

                # Modify header
                header = change_content_length(header, length=len(body))

                final_message = header +b'\n' + body

                # Save the modified data to a new binary file
                save_request_mode1(modifiedFilename, index, final_message)
    
    # >>> All files in a request <<<
    elif ModeFlag==2:
        fileIndex = 0
        # Extract the data between \n\n and the ending sequence
        start_index = request.find(b'\n\n')
        end_index = request.find(end_boundary)
        extracted_data = request[start_index+2:end_index]

        # Split the extracted data using the specified delimiter
        parts = extracted_data.split(start_boundary)[1:]
        
        edited = False
        with tempfile.TemporaryFile() as temp_file:
            for part in parts:
                if fileUploadList[fileIndex]:
                    # Extract parts and edit (just edit some part containing "filename=<filename>")
                    new_filename = get_filename(fileUploadList[fileIndex])
                    new_file_mime = get_mime_type(fileUploadList[fileIndex])
                    new_file_content = read_file_upload(fileUploadList[fileIndex])
                    if b'filename=' in part:
                        edited_part = edit_part(part, new_filename, new_file_mime, new_file_content)
                        temp_file.write(start_boundary + edited_part)
                        edited = True
                        fileIndex += 1
                    else:
                        temp_file.write(start_boundary + part)

            # Check if no part was edited, then append the new part before the footer
            while fileIndex < len(fileUploadList):# Extract parts and edit (just edit some part containing "filename=<filename>")
                new_filename = get_filename(fileUploadList[fileIndex])
                new_file_mime = get_mime_type(fileUploadList[fileIndex])
                new_file_content = read_file_upload(fileUploadList[fileIndex])

                new_part = add_new_part(start_boundary, new_filename, new_file_mime, new_file_content)
                temp_file.write(new_part)
                fileIndex += 1

            # Move file pointer to start of the temp_file
            temp_file.seek(0)

            # Construct final_message
            header = request[:start_index+1]
            edited_data = temp_file.read()
            footer = start_boundary + b'--\n'
            body = edited_data + footer

            # Modify header
            header = change_content_length(body, length=len(body))

            final_message = header + b'\n' + body

            # Save the modified data to a new binary file
            save_request_mode2(modifiedFilename, final_message)
    
    else:
        print("Not support this mode")


def patch_unbound(request, fileUploadList):
    for index, file in enumerate(fileUploadList):
        # Extract parts between \n\n and the ending sequence
        header, body = request.split(b'\n\n', 1)
        header+= b'\n'

        # Replace or add filename
        header = change_header_filename(header, b"PATCH", get_filename(file))

        # Replace or add Content-Type
        header = change_content_type(header, file)

        # Replace or add Content-Length
        header = change_content_length(header, file=file)
  
        # Extract parts and edit (just edit some part containing "filename=<filename>")
        body = read_file_upload(file)
        final_message = header + b"\n" + body

        # Save the modified data to a new binary file
        save_request_mode1(modifiedFilename, index, final_message)
    


def change_file(requestFilePath, fileUploadList):
    # Original request
    request = read_request(requestFilePath)
    boundary = get_boundary(requestFilePath)
    method = get_http_method(requestFilePath)
    if method == 'POST':
        if boundary is not None:
            post_bound(request, boundary, fileUploadList)
            print(">>> Modify requst successful <<<")
        else:
            post_unbound(request, fileUploadList)
            print(">>> Modify requst successful <<<")

    elif method == 'PUT':
        put(request, fileUploadList)
        print(">>> Modify requst successful <<<")

    elif method == 'PATCH':
        if boundary is not None:
            patch_bound(request, boundary, fileUploadList)
            print(">>> Modify requst successful <<<")
        else:
            patch_unbound(request, fileUploadList)
            print(">>> Modify requst successful <<<")
        
    else:
        print(">>> Not found HTTP method supporting files uploading <<<")



change_file(requestFilePath, fileUploadList)
