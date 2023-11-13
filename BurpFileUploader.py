import os
import re
import subprocess
import json
import requests
import tempfile
import magic # pip install python-magic-bin

from burp import (IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation, 
IHttpService, IParameter, IMessageEditorController, IHttpRequestResponse, IProxyListener,
IMessageEditorTabFactory, IMessageEditorTab, IExtensionStateListener )
from javax.swing import (JPanel,
    JTabbedPane,
    JButton,
    JFileChooser,
    JList,
    JScrollPane,
    DefaultListModel,
    JTextArea,
    JLabel,
    BoxLayout,
    JFrame,
    SwingUtilities,
    JMenuBar,
    JMenu,
    JTextField,
    JSplitPane,
    JCheckBox,
    JRadioButton,
    JCheckBoxMenuItem,
    JPopupMenu,
    JTable,
    JViewport,
    JScrollBar,
    JSpinner,
    JSpinner,
    JComboBox,
    JOptionPane)
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color, Font
from burp import IHttpListener
from burp import IContextMenuFactory, IContextMenuInvocation
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from javax.swing import JMenuItem
from java.util import ArrayList


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IContextMenuInvocation):
    
    def __init__(self):
        self.payload_files = DefaultListModel()
        self.payload_files.addElement(None)
        self.current_index = 0
        self.request = None
        self.mode = 1
        self.upload_modes = ["Upload one file per request", "Upload all files in one request"]

        
    def registerExtenderCallbacks(self, callbacks): # for right click on request and send to our function
        self.callbacks = callbacks # set callbacks
        self.helpers = callbacks.getHelpers() # set helpers
        callbacks.registerContextMenuFactory(self)  # registerContextMenuFactory 
        
        # creating a message editor from burp to show request 
        self.requestViewerForPosition = callbacks.createMessageEditor(None, True)
        self.requestViewerForPayload = callbacks.createMessageEditor(None, True)
        self.requestViewerForHistory = callbacks.createMessageEditor(None, True)
        self.responseViewer = callbacks.createMessageEditor(None, True)
        
        # Main UI setup
        self.main_panel = JPanel(BorderLayout())
        self.tabbedPane = JTabbedPane()

        # Tabs
        self.positions_panel = JPanel(BorderLayout())
        self.payloads_panel = JPanel(BorderLayout())
        self.history_panel = JPanel(BorderLayout())


### POSITIONS ###############
        # Fill in the positions panel
        # main for positions is positions_panel
        split_panel_position = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_panel_position.setDividerLocation(250)
        split_panel_position.setBorder(None)

    # Start upload button
        start_upload_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.start_upload_button = JButton("Start upload", actionPerformed=self.start_upload)
        self.start_upload_button.setBackground(Color(255, 102, 51))
        self.start_upload_button.setForeground(Color.WHITE)
        self.start_upload_button.setFont(Font(self.start_upload_button.getFont().getName(), Font.BOLD, self.start_upload_button.getFont().getSize()))
        start_upload_panel.add(self.start_upload_button)
        # Add the top panel to the main panel at the NORTH position
        self.positions_panel.add(start_upload_panel, BorderLayout.NORTH)
    
    # Upload setting panel
        upload_panel = JPanel(BorderLayout())
        control_panel = JPanel(FlowLayout())
        group_panel = JPanel(GridLayout(6,1))

        # Upload Mode
        upload_mode_label = self.createTopicLabel("Upload Mode")
        upload_mode_combo = JComboBox(self.upload_modes)

        # Add action listener to the combo box
        upload_mode_listener = UploadModeActionListener(self, upload_modes=self.upload_modes)
        upload_mode_combo.addActionListener(upload_mode_listener)
        

        # Payloads panel
        target_setting_label = self.createTopicLabel("Target")

        self.target_setting = JTextArea()
        self.target_setting.setEditable(True)  # Make it uneditable
        # self.target_setting.setPreferredSize(Dimension(300, 20)) # set size


        scroll_pane = JScrollPane(self.target_setting)
        scroll_pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)  # Enable horizontal scrolling
        scroll_pane.setPreferredSize(Dimension(500, 33))


        group_panel.add(upload_mode_label)
        group_panel.add(upload_mode_combo)
        group_panel.add(target_setting_label)
        group_panel.add(scroll_pane)

        control_panel.add(group_panel)

        upload_panel.add(control_panel, BorderLayout.WEST)
        upload_panel.setMinimumSize(Dimension(200, 50))
        upload_panel.setMaximumSize(Dimension(600, 300))


    # Request panel
        preview_panel = JPanel(BorderLayout())

        # Preview scrolling button
        group_scrolling_preview = JPanel(FlowLayout(FlowLayout.LEFT))
        self.previous_payload_button = JButton("<", actionPerformed=self.previous_payload)
        self.next_payload_button = JButton(">", actionPerformed=self.next_payload)
        group_scrolling_preview.add(self.previous_payload_button)
        group_scrolling_preview.add(self.next_payload_button)
        
        # Create a JLabel to display the count of items in the list
        self.count_label = JLabel((str(int(self.current_index)) + "  of  " + str(self.payload_files.size()-1)))
        group_scrolling_preview.add(self.count_label)

        # Create the JList to display current file
        self.file_label = JLabel("  " + str(self.payload_files.getElementAt(self.current_index)))
        print(self.payload_files.getElementAt(self.current_index))

        # Request preview mornitoring
        self.editor_viewposition = JTabbedPane()
        self.editor_viewposition.addTab("Request", self.requestViewerForPosition.getComponent())

        # Group topic & scrolling button
        group_header_preview = JPanel(GridLayout(3,1))
        group_header_preview.add(group_scrolling_preview)
        group_header_preview.add(self.file_label)
        preview_panel.add(group_header_preview, BorderLayout.NORTH)
        preview_panel.add(self.editor_viewposition)
        preview_panel.setMinimumSize(Dimension(200, 50))
        preview_panel.setMaximumSize(Dimension(600, 300))
        
        # Add 2 components to split_panel_position and add it to positions_panel
        split_panel_position.setTopComponent(upload_panel)
        split_panel_position.setBottomComponent(preview_panel)
        self.positions_panel.add(split_panel_position, BorderLayout.CENTER)

        self.callbacks.customizeUiComponent(self.editor_viewposition)



### PAYLOADS ###############
        # Panel for splitting payload_setting & request preview
        split_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_panel.setDividerLocation(250)
        split_panel.setBorder(None)
        
    # Start upload button
        start_upload_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.start_upload_button = JButton("Start upload", actionPerformed=self.start_upload)
        self.start_upload_button.setBackground(Color(255, 102, 51))
        self.start_upload_button.setForeground(Color.WHITE)
        self.start_upload_button.setFont(Font(self.start_upload_button.getFont().getName(), Font.BOLD, self.start_upload_button.getFont().getSize()))
        start_upload_panel.add(self.start_upload_button)
        # Add the top panel to the main panel at the NORTH position
        self.payloads_panel.add(start_upload_panel, BorderLayout.NORTH)

    # Payloads panel
        # Set topic
        payload_setting_label = self.createTopicLabel("Payload setting")

        # Add buttons
        self.add_payload_button = JButton("Add File", actionPerformed=self.add_payload)
        self.remove_payload_button = JButton("Remove File", actionPerformed=self.remove_payload)
        self.clear_payload_button = JButton("Clear All", actionPerformed=self.clear_payloads)
        self.preview_payload_button = JButton("Generate", actionPerformed=self.generate_payloads)
        self.payload_list = JList(self.payload_files)

        # Create JScrollPane with fixed size for self.payload_list
        payload_list_scrollpane = JScrollPane(self.payload_list)
        payload_list_scrollpane.setPreferredSize(Dimension(400, 150))  # Set the fixed size as desired

        upload_panel = JPanel(BorderLayout())
        control_panel = JPanel(FlowLayout())
        button_panel = JPanel(GridLayout(6, 1))
        button_panel.add(self.add_payload_button)
        button_panel.add(self.remove_payload_button)
        button_panel.add(self.clear_payload_button)
        button_panel.add(self.preview_payload_button)
        control_panel.add(button_panel)
        control_panel.add(payload_list_scrollpane)
        upload_panel.add(payload_setting_label, BorderLayout.NORTH)
        upload_panel.add(control_panel, BorderLayout.WEST)
        upload_panel.setMinimumSize(Dimension(200, 50))
        upload_panel.setMaximumSize(Dimension(600, 300))


    # Preview panel
        preview_panel = JPanel(BorderLayout())

        # Set topic
        preview_label = self.createTopicLabel("Request preview")
        # Preview scrolling button
        group_scrolling_preview = JPanel(FlowLayout(FlowLayout.LEFT))
        self.previous_payload_button = JButton("<", actionPerformed=self.previous_payload)
        self.next_payload_button = JButton(">", actionPerformed=self.next_payload)
        group_scrolling_preview.add(self.previous_payload_button)
        group_scrolling_preview.add(self.next_payload_button)
        
        # Create a JLabel to display the count of items in the list
        self.count_label = JLabel((str(int(self.current_index)) + "  of  " + str(self.payload_files.size()-1)))
        group_scrolling_preview.add(self.count_label)

        # Create the JList to display current file
        self.file_label = JLabel("  " + str(self.payload_files.getElementAt(self.current_index)))
        print(self.payload_files.getElementAt(self.current_index))

        # Request preview mornitoring
        self.editor_view = JTabbedPane()
        self.editor_view.addTab("Request", self.requestViewerForPayload.getComponent())

        # Group topic & scrolling button
        group_header_preview = JPanel(GridLayout(3,1))
        group_header_preview.add(preview_label)
        group_header_preview.add(group_scrolling_preview)
        group_header_preview.add(self.file_label)
        preview_panel.add(group_header_preview, BorderLayout.NORTH)
        preview_panel.add(self.editor_view, BorderLayout.CENTER)
        preview_panel.setMinimumSize(Dimension(200, 50))
        preview_panel.setMaximumSize(Dimension(600, 300))
        
        # Add 2 components to split_panel and add it to payloads_panel
        split_panel.setTopComponent(upload_panel)
        split_panel.setBottomComponent(preview_panel)
        self.payloads_panel.add(split_panel, BorderLayout.CENTER)

        self.callbacks.customizeUiComponent(self.editor_view)



### HISTORY ###############

        
        
### MAIN ###############
        # Add tabs to main pane
        self.tabbedPane.addTab("Positions", self.positions_panel)
        self.tabbedPane.addTab("Payloads", self.payloads_panel)
        self.tabbedPane.addTab("Upload history", self.history_panel)

        self.main_panel.add(self.tabbedPane, BorderLayout.CENTER)

        # Register the extension
        callbacks.setExtensionName("Files Uploader")
        callbacks.addSuiteTab(self)


    def getTabCaption(self):
        return "Files Uploader"

    def getUiComponent(self):
        return self.main_panel

    def set_position(self, event):
        # Placeholder: This is where the position setting logic will go
        pass


### POSITIONS METHODS ###############
    # Set up mode when select mode at combobox
    def setUploadMode(self, mode_name):
        # Set internal state based on the selected upload mode name
        if mode_name == self.upload_modes[0]:  # "Upload one file per request"
            self.mode = 1
            print("Mode set to {}.".format(mode_name))
        elif mode_name == self.upload_modes[1]:  # "Upload all files in one request"
            self.mode = 2
            print("Mode set to {}.".format(mode_name))
        else:
            print("Unknown Mode")
    

### PAYLOADS METHODS ############### 
    def add_payload(self, event):
        file_chooser = JFileChooser()
        file_chooser.setMultiSelectionEnabled(True)  # Allow multiple file selection
        result = file_chooser.showOpenDialog(self.payloads_panel)

        if result == JFileChooser.APPROVE_OPTION:
            selected_files = file_chooser.getSelectedFiles()
            for file in selected_files:
                # Check for duplicate file uploads 
                if file.getPath() not in self.convert_to_list(self.payload_files):
                    # add path to the payload_files
                    self.payload_files.addElement(file.getPath())
                    if self.current_index == 0:
                        self.current_index = 1
                    self.update_count()
                    self.update_file_label()
                    
    def convert_to_list(self, model):
        return [model.elementAt(i) for i in range(model.size())]
    
    def remove_payload(self, event):
        selected_indices = self.payload_list.getSelectedIndices()
        for index in reversed(selected_indices):  # Reverse to avoid shifting issues
            self.payload_files.remove(index)
            self.current_index = 0
            self.update_count()
            self.update_file_label()

    def clear_payloads(self, event):
        self.payload_files.clear()
        self.payload_files.addElement(None)
        self.current_index = 0
        self.update_count()
        self.update_file_label()
    
    def generate_payloads(self, event):
        # Assuming requestViewerForPosition is your MessageEditor instance
        self.request = self.requestViewerForPosition.getMessage()
        if self.request is not None or len(self.request) != 0:
            if self.payload_files is not None:
                self.manageRequest = ModifyRequest(self.request, self.convert_to_list(self.payload_files), self.mode)
                self.manageRequest.add_file()
                self.requestViewerForPosition.setMessage(self.manageRequest.get_part(1), True)  # setMessage(byte[] message, boolean isRequest)
            else:
                print("Payload files are not set")
        else:
            print("Please fill request in the text editor in position tab")


    def update_count(self):
        self.count_label.setText((str(int(self.current_index)) + "  of  " + str(self.payload_files.size()-1)))
        print(self.payload_files.getElementAt(self.current_index))

    def update_file_label(self):
        self.file_label.setText("  " + str(self.payload_files.getElementAt(self.current_index)))

    def previous_payload(self, event):
        if self.current_index > 1:
            self.current_index -= 1
            self.update_count()
            self.update_file_label()
            self.requestViewerForPosition.setMessage(self.manageRequest.get_part(self.current_index), True)

    def next_payload(self, event):
        if self.current_index < self.payload_files.size() - 1:
            self.current_index += 1
            self.update_count()
            self.update_file_label()
            self.requestViewerForPosition.setMessage(self.manageRequest.get_part(self.current_index), True)



### MAIN METHODS ###############
    def start_upload(self, event):
        pass


    def createTopicLabel(self, topic_text, increaseSizeBy=4): # return JLabel
        # Set topic
        label = JLabel("> " + topic_text + " <")
        # Get the current font of the label
        currentFont = label.getFont()
        # Create a new font object with BOLD style and increased size
        largerBoldFont = Font(currentFont.getName(), Font.BOLD, currentFont.getSize() + increaseSizeBy)
        label.setFont(largerBoldFont)
        return label
    
    # Create a context menu
    def createMenuItems(self, invocation):
        self._invocation = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send to Positions", actionPerformed=self.sendToMyExtension)
        menuList.add(menuItem)
        return menuList
    
    # Handle the action when the context menu item is clicked
    def sendToMyExtension(self, event):
        http_traffic = self._invocation.getSelectedMessages()
        for traffic in http_traffic:
            protocal_bytes = traffic.getProtocol()
            header_bytes = traffic.getHost()
            request_bytes = traffic.getRequest()
            # Display request in the message editor
            self.displayInMyExtension(protocal_bytes, header_bytes, request_bytes)
    
    # Display the request in the message editor
    def displayInMyExtension(self, protocal_bytes, header_bytes, request_bytes):
        print(protocal_bytes + header_bytes)
        self.requestViewerForPosition.setMessage(request_bytes, True)
        self.target_setting.setText(protocal_bytes + b'://' + header_bytes)  # Set the header text

    # These methods are required for the IMessageEditorController interface
    def getHttpService(self):
        return self._invocation.getSelectedMessages()[0].getHttpService()

    def getHost(self):
        return self._invocation.getSelectedMessages()[0].getHeaders()
    
    def getRequest(self):
        return self._invocation.getSelectedMessages()[0].getRequest()

    def getResponse(self):
        return self._invocation.getSelectedMessages()[0].getResponse()


class UploadModeActionListener(ActionListener):
    def __init__(self, extender, upload_modes):
        self._extender = extender
        self._upload_modes = upload_modes

    def actionPerformed(self, event):
        combo_box = event.getSource()
        selected_mode = combo_box.getSelectedItem()

        # Pass the selected mode name to the setUploadMode method
        self._extender.setUploadMode(selected_mode)


class ModifyRequest:
    def __init__(self, request, fileUploadList, mode):
        # fileUpload = "Files_Test/file.png" # For now support image, audio, video, and PDF metadata only
        # outputPath = "output_file.bin"
        # fileUploadList = ["Files_Test/file.json", "Files_Test/file.png","Files_Test/s_file.pdf", "Files_Test/s_file.docx"]
        # ModeFlag = 0 # ModeFlag = 0 (not set), 1 (a file per request), 2 (all files in a request)
        # BoundaryFlag = 0 # BoundaryFlag = 0 (no boundary), 1 (have boundary)
        # Special character for separation, for example, a newline
        
        self.requestFilePath = "request.bin"
        self.separator = b'\n--*--\n-*-*-\n-*-BurpExtensionByFolk44-*-\n-*-*-\n--*--\n'
        self.modifiedFilename = "output_file.bin"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.part_files = []

        self.fileUploadList = fileUploadList # file path list
        self.ModeFlag = mode # 1 (a file per request), 2 (all files in a request)

        with open(request, 'wb') as request_file:
            request_file.write(self.request)

        self.boundary = self.get_boundary()
        self.method = self.get_http_method()
        self.request = self.read_request() # Binary

    # REQUEST #################
    def read_request(self):
        with open(self.requestFilePath, 'rb') as file:
            data = file.read()
            file.close()
            return data # Binary

    def get_http_method(self):
        with open(self.requestFilePath, 'rb') as f:
            first_line = f.readline()
            match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s', first_line.decode('utf-8')) # \s matches any whitespace character, including tabs.
            if match:
                return match.group(1) # utf-8
            else:
                print("HTTP Method not found!")
                return None

    def get_boundary(self):
        # Regular expression to find the boundary value (adapted for bytes)
        match = re.search(b'boundary=(.+?)\n', self.request)
        
        if match:
            boundary_value = match.group(1)
            # print("boundary=", boundary_value.decode('utf-8', 'ignore'))
            return boundary_value # binary
        else:
            print("Have no boundary")
            self.ModeFlag = 1
            return None

    def add_new_part(self, boundary, new_filename, new_content_type, new_binary_content):
        return self.boundary + b'\n' + \
            b'Content-Disposition: form-data; name="file"; filename=' + new_filename + b'\n' + \
            b'Content-Type: ' + new_content_type + b'\n\n' + \
            new_binary_content + b'\n'

    def edit_part(self, part, new_filename, new_content_type, new_binary_content):
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
    def get_mime_type(self, filename):
        mime = magic.Magic(mime=True)
        return (mime.from_file(filename)).encode()

    def get_content_length(self, filename):
        return str(os.path.getsize(filename)).encode()

    def get_filename(self, filename):
        return (os.path.basename(filename)).encode()

    def read_file_upload(self, filename):
        with open(filename, 'rb') as file:
            content = file.read()
            file.close()
            return content # Binary



    # MAIN METHOD #################
    def save_binary_file(self, new_filename, content):
        with open(new_filename, "wb") as f:
            f.write(content)
            f.close()
        print("Message saved to {}".format(new_filename))

    def save_request_mode1(self, filename, index, message):
        if index == 0:
            with open(filename, 'wb') as f:
                f.write(message + self.separator)
                print("File number {} was added".format(index))
        else:
            with open(filename, 'ab') as f:
                f.write(message + self.separator)
                print("File number {} was added".format(index))

    def save_request_mode2(self, filename, message):
        # Save the modified data to a new binary file
        with open(filename, 'wb') as f:
            f.write(message)

    def change_header_filename(self, part, method, new_filename):
        # Regex to match the pattern
        pattern = self.method + rb' (.*/).* (.+\n)'
        part = re.sub(pattern, self.method + rb' \1' + new_filename + rb' \2', part)
        return part

    def change_content_type(self, part, file):
        # Replace or add Content-Type
        if b"Content-Type:" in part:
            part = re.sub(rb"Content-Type: .+?(?=;|\n)", b"Content-Type: " + get_mime_type(file), part)
        else:
            part += b"Content-Type: {}\n".format(get_mime_type(file))
        return part

    def change_content_length(self, part, length=0, file=None):
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
    def post_bound(self):
        start_boundary = b'--' + self.boundary
        end_boundary = start_boundary + b'--'

        # >>> One file per request <<<
        if self.ModeFlag == 1:
            for index, file in enumerate(self.fileUploadList):
                # Extract the data between \n\n and the ending sequence
                start_index = self.request.find(b'\n\n')
                end_index = self.request.find(end_boundary)
                extracted_data = self.request[start_index+2:end_index]

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
                    header = self.request[:start_index+1]
                    edited_data = temp_file.read()
                    footer = start_boundary + b'--\n'
                    body = edited_data + footer
                    final_message = header + b'\n' + body

                    # Save the modified data to a new binary file
                    save_request_mode1(modifiedFilename, index, final_message)
        
        # >>> All files in a request <<<
        elif self.ModeFlag==2:
            fileIndex = 0
            # Extract the data between \n\n and the ending sequence
            start_index = self.request.find(b'\n\n')
            end_index = self.equest.find(end_boundary)
            extracted_data = self.request[start_index+2:end_index]

            # Split the extracted data using the specified delimiter
            parts = extracted_data.split(start_boundary)[1:]
            
            edited = False
            with tempfile.TemporaryFile() as temp_file:
                for part in parts:
                    if self.fileUploadList[fileIndex]:
                        # Extract parts and edit (just edit some part containing "filename=<filename>")
                        new_filename = get_filename(self.fileUploadList[fileIndex])
                        new_file_mime = get_mime_type(self.fileUploadList[fileIndex])
                        new_file_content = read_file_upload(self.fileUploadList[fileIndex])
                        if b'filename=' in part:
                            edited_part = edit_part(part, new_filename, new_file_mime, new_file_content)
                            temp_file.write(start_boundary + edited_part)
                            edited = True
                            fileIndex += 1
                        else:
                            temp_file.write(start_boundary + part)

                # Check if no part was edited, then append the new part before the footer
                while fileIndex < len(self.fileUploadList):# Extract parts and edit (just edit some part containing "filename=<filename>")
                    new_filename = get_filename(self.fileUploadList[fileIndex])
                    new_file_mime = get_mime_type(self.fileUploadList[fileIndex])
                    new_file_content = read_file_upload(self.fileUploadList[fileIndex])

                    new_part = add_new_part(start_boundary, new_filename, new_file_mime, new_file_content)
                    temp_file.write(new_part)
                    fileIndex += 1

                # Move file pointer to start of the temp_file
                temp_file.seek(0)

                # Construct final_message
                header = self.request[:start_index+2]
                edited_data = temp_file.read()
                footer = start_boundary + b'--\n'
                final_message = header + edited_data + footer

                # Save the modified data to a new binary file
                save_request_mode2(modifiedFilename, final_message)
        
        else:
            print("Not support this mode")

    def post_unbound(self):
        for index, file in enumerate(self.fileUploadList):
            # Extract parts between \n\n and the ending sequence
            header, body = self.request.split(b'\n\n', 1)
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

    def put(self):
        for index, file in enumerate(self.fileUploadList):
            # Extract parts between \n\n and the ending sequence
            header, body = self.request.split(b'\n\n', 1)
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

    def patch_bound(self):
        start_boundary = b'--' + self.boundary
        end_boundary = start_boundary + b'--'

        # >>> One file per request <<<
        if self.ModeFlag == 1:
            for index, file in enumerate(self.fileUploadList):
                # Extract the data between \n\n and the ending sequence
                start_index = self.request.find(b'\n\n')
                end_index = self.request.find(end_boundary)
                extracted_data = self.request[start_index+2:end_index]

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
                    header = self.request[:start_index+1]
                    edited_data = temp_file.read()
                    footer = start_boundary + b'--\n'
                    body = edited_data + footer

                    # Modify header
                    header = change_content_length(header, length=len(body))

                    final_message = header +b'\n' + body

                    # Save the modified data to a new binary file
                    save_request_mode1(modifiedFilename, index, final_message)
        
        # >>> All files in a request <<<
        elif self.ModeFlag==2:
            fileIndex = 0
            # Extract the data between \n\n and the ending sequence
            start_index = self.request.find(b'\n\n')
            end_index = self.request.find(end_boundary)
            extracted_data = self.request[start_index+2:end_index]

            # Split the extracted data using the specified delimiter
            parts = extracted_data.split(start_boundary)[1:]
            
            edited = False
            with tempfile.TemporaryFile() as temp_file:
                for part in parts:
                    if self.fileUploadList[fileIndex]:
                        # Extract parts and edit (just edit some part containing "filename=<filename>")
                        new_filename = get_filename(self.fileUploadList[fileIndex])
                        new_file_mime = get_mime_type(self.fileUploadList[fileIndex])
                        new_file_content = read_file_upload(self.fileUploadList[fileIndex])
                        if b'filename=' in part:
                            edited_part = edit_part(part, new_filename, new_file_mime, new_file_content)
                            temp_file.write(start_boundary + edited_part)
                            edited = True
                            fileIndex += 1
                        else:
                            temp_file.write(start_boundary + part)

                # Check if no part was edited, then append the new part before the footer
                while fileIndex < len(self.fileUploadList):# Extract parts and edit (just edit some part containing "filename=<filename>")
                    new_filename = get_filename(self.fileUploadList[fileIndex])
                    new_file_mime = get_mime_type(self.fileUploadList[fileIndex])
                    new_file_content = read_file_upload(self.fileUploadList[fileIndex])

                    new_part = add_new_part(start_boundary, new_filename, new_file_mime, new_file_content)
                    temp_file.write(new_part)
                    fileIndex += 1

                # Move file pointer to start of the temp_file
                temp_file.seek(0)

                # Construct final_message
                header = self.request[:start_index+1]
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


    def patch_unbound(self):
        for index, file in enumerate(self.fileUploadList):
            # Extract parts between \n\n and the ending sequence
            header, body = self.request.split(b'\n\n', 1)
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
        


    def add_file(self):
        if self.method == 'POST':
            if self.boundary is not None:
                post_bound()
                print(">>> Modify requst successful <<<")
            else:
                post_unbound()
                print(">>> Modify requst successful <<<")

        elif self.method == 'PUT':
            put()
            print(">>> Modify requst successful <<<")

        elif self.method == 'PATCH':
            if self.boundary is not None:
                patch_bound()
                print(">>> Modify requst successful <<<")
            else:
                patch_unbound()
                print(">>> Modify requst successful <<<")
            
        else:
            print(">>> Not found HTTP method supporting files uploading <<<")

    
    # Get each part of request #################
    def read_and_split_modified_request(self):
        # Reads the file and splits it into parts, storing each part in a temporary file.
        try:
            with open(self.modifiedFilename, 'rb') as file:
                content = file.read()

            parts = content.split(self.separator)
            for i, part in enumerate(parts):
                part_file_path = os.path.join(self.temp_dir.name, f'part_{i}')
                with open(part_file_path, 'wb') as part_file:
                    part_file.write(part)
                self.part_files.append(part_file_path)
        except Exception as e:
            raise IOError(f"An error occurred while reading the file: {e}")

    def get_part(self, part_number):
        # Returns the content of the requested part from the temporary file.
        if not self.part_files:
            self.read_and_split_modified_request()

        if part_number < 1 or part_number > len(self.part_files):
            return f"Invalid part number. There are only {len(self.part_files)} parts."

        with open(self.part_files[part_number - 1], 'rb') as part_file:
            return part_file.read()

    def cleanup(self):
        # Cleans up the temporary files and directory.
        self.temp_dir.cleanup()


