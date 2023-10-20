import re
import subprocess
import json
import requests
import tempfile

requestFilePath = "request.txt"
fileUpload = "Files_Test/file.pdf" # For now support image, audio, video, and PDF metadata only
outputPath = "output_file.bin"
flagMode = 0 # flag_mode = 0 (no boundary), 1 (have boundary)



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
    content = read_request(requestFilePath)

    # Regular expression to find the boundary value (adapted for bytes)
    match = re.search(b'boundary=(.+?)\r\n', content)
    
    if match:
        boundary_value = match.group(1)
        # print("boundary=", boundary_value.decode('utf-8', 'ignore'))
        return boundary_value # binary
    else:
        print("Boundary value not found!")
        return None


def add_new_part(boundary, new_filename, new_content_type, new_binary_content):
    return boundary + b'\r\n' + \
           b'Content-Disposition: form-data; name="file"; filename=' + new_filename + b'\r\n' + \
           b'Content-Type: ' + new_content_type + b'\r\n\r\n' + \
           new_binary_content + b'\r\n'


def edit_part(part, new_filename, new_content_type, new_binary_content):
    # Use regular expressions to identify and replace the filename and Content-Type
    part = re.sub(b'(filename=")[^"]*(")', b'\\1' + new_filename + b'\\2', part)
    
    # Check if the Content-Type is present and replace it, otherwise add it
    if b'Content-Type:' in part:
        part = re.sub(b'(Content-Type: )[^\r\n]*', b'\\1' + new_content_type, part)
    else:
        position = part.find(b'\r\n\r\n')
        part = part[:position] + b'\r\nContent-Type: ' + new_content_type + part[position:]
    
    # Find the start position of old binary content
    position = part.find(b'\r\n\r\n') + 4
        # Find the end position of old binary content. If we're assuming that the old binary content ends 
        # just before the next boundary or the end of the part, we can use the end of the part as the position.
    end_position = len(part)

    # Replace the old content with new_binary_content
    part = part[:position] + new_binary_content + b'\r\n' + part[end_position:]
    
    return part



# FILE UPLOAD #################       
def get_all_file_info(filename):
    try:
        # Use ExifTool to extract metadata from the file
        # The `-j` flag outputs the data in JSON format
        result = subprocess.check_output(["exiftool", "-j", filename])

        # Parse the JSON output
        info = json.loads(result.decode('utf-8'))

        # Return the first item in the list (as each file's info is a separate item in the list)
        return info[0] # utf-8
    except subprocess.CalledProcessError as e:
        print(f"Error running exiftool: {e}")
        return None


def get_file_info(filename, keys_list=["FileName", "MIMEType"]):
    info = get_all_file_info(filename)
    if info is None:
        return None
    try:
        extracted_values = [info[key] for key in keys_list if key in info]
        return extracted_values # List (utf-8)
    except Exception as e:
        print(e)
        return None


def get_files_info(filenames, keys_list=["FileName", "MIMEType"]):
    all_files_info = []
    for filename in filenames:
        file_info = get_file_info(filename, keys_list)
        if file_info is not None:
            all_files_info.append(file_info)
    return all_files_info


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


def change_file(requestFilePath, fileUpload):
    # Original request
    request = read_request(requestFilePath)
    boundary = get_boundary(requestFilePath)
    start_boundary = b'--' + boundary
    end_boundary = start_boundary + b'--'

    # Extract the data between \r\n\r\n and the ending sequence
    start_index = request.find(b'\r\n\r\n')
    end_index = request.find(end_boundary)
    extracted_data = request[start_index+4:end_index]

    # Split the extracted data using the specified delimiter
    parts = extracted_data.split(start_boundary)[1:]
     
    # Extract parts and edit (just edit some part containing "filename=<filename>")
    new_file_info = [x.encode() for x in (get_file_info(fileUpload))] # converted to binary
    new_file_content = read_file_upload(fileUpload)
    
    edited = False # To keep track if any part was edited
    already_edited = False  # To monitor if we've edited a "filename=" part
    # Create a temporary file to store edited parts
    with tempfile.TemporaryFile() as temp_file:
        for part in parts:
            if b'filename=' in part and not already_edited:
                edited_part = edit_part(part, new_file_info[0], new_file_info[1], new_file_content)
                temp_file.write(start_boundary + edited_part)
                already_edited = True
                edited = True
            else:
                temp_file.write(start_boundary + part)

        # Check if no part was edited, then append the new part before the footer
        if not edited:
            new_part = add_new_part(start_boundary, new_file_info[0], new_file_info[1], new_file_content)
            temp_file.write(new_part)

        # Move file pointer to start of the temp_file
        temp_file.seek(0)

        # Construct final_message
        header = request[:start_index+4]
        edited_data = temp_file.read()
        footer = start_boundary + b'--\r\n'
        final_message = header + edited_data + footer

        # Save the modified data to a new binary file
        with open('output_file.bin', 'wb') as f:
            f.write(final_message)
    print(">>> Modify requst successful <<<")
    


change_file(requestFilePath, fileUpload)
