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

        
    def registerExtenderCallbacks(self, callbacks): # for right click on request and send to our function
        self.callbacks = callbacks # set callbacks
        self.helpers = callbacks.getHelpers() # set helpers
        callbacks.registerContextMenuFactory(self)  # registerContextMenuFactory 
        
        # creating a message editor from burp to show request 
        self.requestViewer = callbacks.createMessageEditor(None, True)
        self.requestViewerforposition = callbacks.createMessageEditor(None, True)
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
        self.upload_modes = ["Upload one file per request", "Upload all files in one request"]
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
        self.editor_viewposition.addTab("Request", self.requestViewerforposition.getComponent())

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
        self.editor_view.addTab("Request", self.requestViewer.getComponent())

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
    def setUploadMode(self, mode_name):
        # Set internal state based on the selected upload mode name
        if mode_name == self.upload_modes[0]:  # "Upload one file per request"
            self.single_file_upload = True
        elif mode_name == self.upload_modes[1]:  # "Upload all files in one request"
            self.single_file_upload = False
        print("Mode set to {}.".format(mode_name))
    

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
        pass

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

    def next_payload(self, event):
        if self.current_index < self.payload_files.size() - 1:
            self.current_index += 1
            self.update_count()
            self.update_file_label()
    


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
        self.requestViewerforposition.setMessage(request_bytes, True)
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

