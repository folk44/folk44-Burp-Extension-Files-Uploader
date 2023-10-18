from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTabbedPane, JTable, JButton, JScrollPane, BorderFactory,JFileChooser, JList, DefaultListModel, JTextArea, JLabel, BoxLayout, JFrame, SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color, Font

# Redo the file from the beginning, so that I understand the entire process of how javax.swing and java.awt works

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers() 
        
        print("Window messages") # This will show up in "Load Burp extension" window's Output
        callbacks.issueAlert("Log messages") # This will show up up Burp Suite Dashboard log
        
        # Setting up the UI, at this stage, the Tab is not yet added to Burp Suite.
        self.main_panel = JPanel(BorderLayout())
        self.tabbedPane = JTabbedPane()

        # ====================== HISTORY PANEL ======================

        # Create a panel to hold the table and add a border to it
        table_panel = JPanel(BorderLayout())
        # Add an empty border with padding around the panel, (TOP, LEFT, BOTTOM, RIGHT)
        table_panel.setBorder(BorderFactory.createEmptyBorder(10, 25, 25, 25))  # Adjust the values for padding

        # Test data for the table
        test_data = [["1", "www.google.com"], ["2", "www.youtube.com"]]

        # Column names
        column_names = ["#", "URL", "Method", "File Path", "Status Code", "Length", "Time"]

        # Add table model
        self.table_model = DefaultTableModel(test_data, column_names)

        # Create a table based on the model
        self.table = JTable(self.table_model)

        # Create a scroll pane to hold the table
        scroll_pane = JScrollPane(self.table)

        # Add the scroll pane to the table panel
        table_panel.add(scroll_pane, BorderLayout.CENTER)

        # Create a panel and set its layout
        self.history_panel = JPanel()
        self.history_panel.setLayout(BorderLayout())

        # Add the table panel to the history panel
        self.history_panel.add(table_panel, BorderLayout.CENTER)


        # =========== Start Upload Button in History panel ================

        start_upload_panel = JPanel(FlowLayout(FlowLayout.RIGHT))

        # Add an empty border with padding around the panel, (TOP, LEFT, BOTTOM, RIGHT)
        start_upload_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 20))  # Adjust the values for padding

        self.start_upload_button = JButton("Start upload", actionPerformed=self.start_upload)
        self.start_upload_button.setBackground(Color(255, 102, 51))
        self.start_upload_button.setForeground(Color.WHITE)
        self.start_upload_button.setFont(Font(self.start_upload_button.getFont().getName(), Font.BOLD, self.start_upload_button.getFont().getSize()))
        start_upload_panel.add(self.start_upload_button)
        # Add the top panel to the main panel at the NORTH position
        self.history_panel.add(start_upload_panel, BorderLayout.NORTH)

        # ====================== MAIN PANEL =========================

        # Add tabs to the tabbedPane
        self.tabbedPane.addTab("Upload history", self.history_panel)

        # Add tabbedPane to the main_panel
        # East = Right, West = Left, North = Top (same as left), CENTER = same as left, South = Bottom
        self.main_panel.add(self.tabbedPane, BorderLayout.CENTER)

        # Register the extension
        callbacks.setExtensionName("File Upload History")
        callbacks.addSuiteTab(self)


    # Only wheb getTabCaption and getUiCoponent are defined, the extension will be added to Burp Suite

    def getTabCaption(self):
        return "Files Uploader History"

    def getUiComponent(self):
        return self.main_panel
    
    # ====================== Main Method ======================

    def start_upload(self, event):
        pass