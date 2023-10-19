import re
import subprocess
import json
import requests

requestFilePath = "request.txt"
fileUpload = "Myfilecopy.png"
outputPath = "output_file.bin"
flagMode = 0 # flag_mode = 0 (no boundary), 1 (have boundary)



# REQUEST #################
def read_request(requestFilePath):
    with open(requestFilePath, 'rb') as file:
        data = file.read()
        # print(type(data)) # Binary
        # print(data)
        file.close()
        return data # Binary
# print(read_request(requestFilePath))


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
        print("boundary=", boundary_value.decode('utf-8', 'ignore'))
        return boundary_value # binary
    else:
        print("Boundary value not found!")
        return None


def add_new_part(new_filename, new_content_type, new_binary_content):
    return b'\r\n' + \
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
    edited_parts = []
    for part in parts:
        if b'filename=' in part and not already_edited:
            edited_part = edit_part(part, new_file_info[0], new_file_info[1], new_file_content)
            edited_parts.append(edited_part)
            edited = True
            already_edited = True
        else:
            edited_parts.append(part)

    if not edited:
        new_part = add_new_part(new_file_info[0], new_file_info[1], new_file_content)
        edited_parts.append(new_part)

    # Reconstruct the entire message
    header = request[:start_index+4]
    footer = end_boundary
    final_message = header + start_boundary + start_boundary.join(edited_parts) + footer

    # If you want to save the final_message to a file
    with open(outputPath, 'wb') as f:
        f.write(final_message)
        f.close()

    # If you want to inspect the final_message in the console
    print(final_message.decode('utf-8', 'ignore'))


change_file(requestFilePath, fileUpload)


# fileInfo = get_file_info(fileUpload) # List


# boundary_value, EOR = get_boundary(requestFilePath)
# print(boundary_value)
# getBoundary(requestFilePath)



# import requests

# # Create a Request object without sending it
# req = requests.Request(
#     method='POST',
#     url='127.0.0.1/',
#     data={
#         'param1': 'value1',
#         'param2': 'value2'
#     },
#     files={
#         'file': ('filename.ext', open('Myfilecopy.png', 'rb'))
#     },
#     headers={
#         'User-Agent': 'MyApp/1.0'
#     }
# )

# # Use a session to prepare the request
# prepared_req = req.prepare()

# # Now you can inspect various properties of the prepared request
# print("Method:", prepared_req.method)
# print("URL:", prepared_req.url)
# print("Headers:", prepared_req.headers)
# print("Body:", prepared_req.body)  # Note: this may be in bytes

# # Prompt the user for confirmation
# confirm = input("Do you want to send the request? (yes/no): ")
# if confirm.lower() == 'yes':
#     with requests.Session() as s:
#         response = s.send(prepared_req)
#         print(response.text)



# import requests

# def send_file_to_server(file_path, url):
#     # Define the proxies to route through Burp Suite
#     proxies = {
#         "http": "http://127.0.0.1:8080",
#         "https": "https://127.0.0.1:8080",
#     }

#     # Open the file in binary mode and send it as part of a multipart/form-data POST request
#     with open(file_path, 'rb') as f:
#         files = {'file': (file_path.split('/')[-1], f)} # get file name form path  # <class 'dict'>
#         response = requests.post(url, files=files, proxies=proxies)
#     return response.text

# if __name__ == '__main__':
#     file_path = file_upload # Change this to the path of your file
#     url = 'http://foophones.securitybrigade.com:8080/register_confirm.php' # Change this to your server's URL
#     print(send_file_to_server(file_path, url))
