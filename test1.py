from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel,
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
    JMenuItem,
    JTextField,
    
)
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color, Font
from burp import IHttpListener
from burp import IContextMenuFactory, IContextMenuInvocation
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JMenuItem

class BurpExtender(
    IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IContextMenuInvocation
):
    # MENU ITEM
    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        menu = []
        menu.append(
            JMenuItem(
                "Payloads",
                actionPerformed=lambda x, inv=invocation: self.copyUrl(x, inv),
            )
        )
        menu.append(
            JMenuItem(
                "Positions",
                actionPerformed=lambda x, inv=invocation: self.copyUrl(x, inv),
            )
        )
        menu.append(
            JMenuItem(
                "Upload History",
                actionPerformed=lambda x, inv=invocation: self.copyUrl(x, inv),
            )
        )
        if menu == []:
            return
        else:
            return menu

    def __init__(self):
        self.payload_files = DefaultListModel()
        self.payload_files.addElement(None)
        self.current_index = 0
    #self is the object of the class
    def registerExtenderCallbacks(self, callbacks):  # registerExtenderCallbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("File Uploader1")  # setExtensionName
        callbacks.registerContextMenuFactory(self)  # registerContextMenuFactory
        # Main UI setup
        self.main_panel = JPanel(BorderLayout())
        self.tabbedPane = JTabbedPane()

        # Tabs
        self.positions_panel = JPanel(BorderLayout())
        self.payloads_panel = JPanel(
            BorderLayout()
        )  # This will be the main panel for the payloads tab
        self.history_panel = JPanel(BorderLayout())











        ########### POSITIONS ###############
        # Fill in the positions panel
        # Start upload button
        panel = JPanel()
        start_upload__panel = JPanel(FlowLayout()) # need to fix to border layout
        self.start_upload_button = JButton(
            "Start upload", actionPerformed=self.start_upload
        )
        
        self.start_upload_button.setBackground(Color(255, 102, 51))
        self.start_upload_button.setForeground(Color.WHITE)
        self.start_upload_button.setFont(
            Font(
                self.start_upload_button.getFont().getName(),
                Font.BOLD,
                self.start_upload_button.getFont().getSize(),
            )
        )
        start_upload__panel.add(self.start_upload_button)
        button_panel = JPanel(GridLayout(6, 1))
        # Add the top panel to the main panel at the NORTH position
        
        
        self.positions_panel.add(start_upload__panel, BorderLayout.EAST)
        # Add, Clear, Auto
        self.add_payload_position_button = JButton("Add", actionPerformed=self.add_payload)
        self.clear_payload_position_button = JButton("Clear", actionPerformed=self.clear_payloads)
        self.auto_payload_position_button = JButton("Auto", actionPerformed=self.preview_payloads)
        start_upload__panel.add(self.add_payload_position_button, BorderLayout.WEST)
        start_upload__panel.add(self.clear_payload_position_button, BorderLayout.CENTER)
        start_upload__panel.add(self.auto_payload_position_button, BorderLayout.EAST)
        def add_payload(self,event):
            pass
        
        # Start upload mode panel
        
        upload_mode_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        upload_mode_label = self.createTopicLabel("Upload mode")
        upload_mode_panel.add(upload_mode_label)
        # Add the upload mode panel to the main panel at the WEST position
        self.positions_panel.add(upload_mode_panel, BorderLayout.WEST) # border layout

        
        # menu
        def OnClick(event):
            txt.text = event.getActionCommand()
        
        bar = JMenuBar()
        bar.setPreferredSize(Dimension(200, 20)) # set size
        file = JMenu()
        file.setPreferredSize(Dimension(200, 20)) # set size
        Upload_one_file = JMenuItem("Upload one file per one request",actionPerformed = OnClick) #menu item
        Upload_all_file = JMenuItem("Upload all files per one request",actionPerformed = OnClick) #menu item
        file.add(Upload_one_file) # add menu item
        file.add(Upload_all_file) # add menu item
        bar.add(file) # add menu
        upload_mode_panel.add(bar) # add menu to panel
        # end menu
        
        # payload position panel
        payload_position_panel = JPanel(BorderLayout())
        payload_position_label = self.createTopicLabel("Payload position")
        payload_position_panel.add(payload_position_label)
        self.positions_panel.add(payload_position_panel)
        # payload target panel
        payload_target_panel = JPanel(BorderLayout())
        payload_target_textarea = JTextArea(50, 50)
        payload_target_panel.add(payload_target_textarea)
        self.positions_panel.add(payload_target_panel)
        
        


        
























        ### PAYLOADS ###############

        # Start upload button
        start_upload__panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.start_upload_button = JButton(
            "Start upload", actionPerformed=self.start_upload
        )
        self.start_upload_button.setBackground(Color(255, 102, 51))
        self.start_upload_button.setForeground(Color.WHITE)
        self.start_upload_button.setFont(
            Font(
                self.start_upload_button.getFont().getName(),
                Font.BOLD,
                self.start_upload_button.getFont().getSize(),
            )
        )
        start_upload__panel.add(self.start_upload_button)
        # Add the top panel to the main panel at the NORTH position
        self.payloads_panel.add(start_upload__panel, BorderLayout.NORTH)

        # Payloads panel
        # # Set topic
        payload_label = self.createTopicLabel("Payload setting")

        # Add buttons
        self.add_payload_button = JButton("Add File", actionPerformed=self.add_payload)
        self.remove_payload_button = JButton(
            "Remove File", actionPerformed=self.remove_payload
        )
        self.clear_payload_button = JButton(
            "Clear All", actionPerformed=self.clear_payloads
        )
        self.preview_payload_button = JButton(
            "Preview", actionPerformed=self.preview_payloads
        )
        self.payload_list = JList(self.payload_files)

        # Create JScrollPane with fixed size for self.payload_list
        payload_list_scrollpane = JScrollPane(self.payload_list)
        payload_list_scrollpane.setPreferredSize(
            Dimension(400, 150)
        )  # Set the fixed size as desired

        upload_panel = JPanel(BorderLayout())
        control_panel = JPanel(FlowLayout())
        button_panel = JPanel(GridLayout(6, 1))
        button_panel.add(self.add_payload_button)
        button_panel.add(self.remove_payload_button)
        button_panel.add(self.clear_payload_button)
        button_panel.add(self.preview_payload_button)
        control_panel.add(button_panel)
        control_panel.add(payload_list_scrollpane)
        upload_panel.add(payload_label, BorderLayout.NORTH)
        upload_panel.add(control_panel, BorderLayout.WEST)

        # Add components to payloads panel
        self.payloads_panel.add(upload_panel, BorderLayout.WEST)

        # Preview panel
        preview_panel = JPanel(BorderLayout())
        # Set topic
        preview_label = self.createTopicLabel("Request preview")
        # Preview scrolling button
        group_scrolling_preview = JPanel(FlowLayout(FlowLayout.LEFT))
        self.previous_payload_button = JButton(
            "<", actionPerformed=self.previous_payload
        )
        self.next_payload_button = JButton(">", actionPerformed=self.next_payload)
        group_scrolling_preview.add(self.previous_payload_button)
        group_scrolling_preview.add(self.next_payload_button)

        # Create a JLabel to display the count of items in the list
        self.count_label = JLabel(
            (
                str(int(self.current_index))
                + "  of  "
                + str(self.payload_files.size() - 1)
            )
        )
        group_scrolling_preview.add(self.count_label)

        # Create the JList to display current file
        self.file_label = JLabel(self.payload_files.getElementAt(self.current_index))
        print(self.payload_files.getElementAt(self.current_index))

        # Request preview mornitoring
        self.preview_textarea = JTextArea(10, 50)
        self.preview_textarea.setEditable(True)

        # Group topic & scrolling button
        group_header_preview = JPanel(GridLayout(4, 1))
        group_header_preview.add(preview_label)
        group_header_preview.add(group_scrolling_preview)
        group_header_preview.add(self.file_label)
        preview_panel.add(group_header_preview, BorderLayout.NORTH)
        preview_panel.add(JScrollPane(self.preview_textarea), BorderLayout.CENTER)

        # Add components to payloads panel
        self.payloads_panel.add(preview_panel, BorderLayout.SOUTH)

        ### HISTORY ###############
        # Fill in the history panel (just a placeholder for now)
        self.history_text = JTextArea(25, 50)
        self.history_panel.add(JScrollPane(self.history_text))

        ### MAIN ###############
        # Add tabs to main pane
        self.tabbedPane.addTab("Positions", self.positions_panel)
        self.tabbedPane.addTab("Payloads", self.payloads_panel)
        self.tabbedPane.addTab("Upload history", self.history_panel)

        self.main_panel.add(self.tabbedPane, BorderLayout.CENTER)

        # Register the extension
        callbacks.setExtensionName("File Uploader1")
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "File Uploader1"

    def getUiComponent(self):
        return self.main_panel

    def set_position(self, event):
        # Placeholder: This is where the position setting logic will go
        pass

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
                    self.update_count()

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

    def preview_payloads(self, event):
        pass

    def update_count(self):
        self.count_label.setText(
            (
                str(int(self.current_index))
                + "  of  "
                + str(self.payload_files.size() - 1)
            )
        )
        print(self.payload_files.getElementAt(self.current_index))

    def update_file_label(self):
        self.file_label.setText(self.payload_files.getElementAt(self.current_index))

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
    def createTopicLabel(self, topic_text, increaseSizeBy=4):  # return JLabel
        # Set topic
        label = JLabel("> " + topic_text + " <")
        # Get the current font of the label
        currentFont = label.getFont()
        # Create a new font object with BOLD style and increased size
        largerBoldFont = Font(
            currentFont.getName(), Font.BOLD, currentFont.getSize() + increaseSizeBy
        )
        label.setFont(largerBoldFont)
        return label
