from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (JPanel, JTabbedPane, JTable, JButton, JScrollPane, JSplitPane, BorderFactory,
JFileChooser, JList, DefaultListModel, JTextArea, JLabel, BoxLayout, JFrame, SwingUtilities)
from javax.swing.table import ( DefaultTableModel, AbstractTableModel, TableRowSorter ,TableCellEditor)
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color, Font

from javax.swing.SwingConstants import VERTICAL

from javax.swing.event import ListSelectionListener

# Redo the file from the beginning, so that I understand the entire process of how javax.swing and java.awt works

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers() 
        
        callbacks.issueAlert("Log messages") # This will show up up Burp Suite Dashboard log
        callbacks.setExtensionName("File Upload History v2")

        # Creating outputs after loading
        print("File Upload History Testing Version") # This will show up in "Load Burp extension" window's Output

        # Register a factory for creating context menu items (Ex. Proxy -> HTTP history, Target -> Site map, etc.)
        callbacks.registerContextMenuFactory(self)

        # Setting up the UI, at this stage, the Tab is not yet added to Burp Suite.
        self.tab = JPanel(BorderLayout())
        self.tabbedPane = JTabbedPane()
        self.tab.add("Center", self.tabbedPane)

        # =============================================================================
        # ====================== First Tab (FIle Upload History) ======================
        # =============================================================================
       
        # Creating a tab name tab "File Upload History" in the extension tab
        self.firstTab = JPanel()
        self.firstTab.layout = BorderLayout()
        self.tabbedPane.addTab("File Upload History", self.firstTab)
        callbacks.addSuiteTab(self)

        # ====================== Start Upload Panel + Button ======================

        # Create a panel for the "Start Upload" button, and also a button
        self.startUploadButtonPanel = JPanel()
        self.startUploadButtonPanel.add(JButton("Start Upload", actionPerformed=self.startUpload))
        # Add the panel into third tab
        self.firstTab.add(self.startUploadButtonPanel, BorderLayout.PAGE_START)

        # ====================== Table Panel + Scroll Pane =======================

        # Creating a table tab in "File Upload History" tab
        self.tablePanel = JPanel()
        self.colNames = ('#', 'URL', 'Method', 'File Path', 'Status Code', 'Length', 'Time')
        self.dataModel = CustomDefaultTableModelHosts(None, self.colNames)
        self.table = JTable(self.dataModel)
        self.table.getTableHeader().setReorderingAllowed(False)
        self.table.setAutoCreateRowSorter(True)

        # Create a scroll pane to hold the table
        self.scrollPane = JScrollPane(self.table)
        self.sorter = TableRowSorter(self.dataModel)
        self.table.setRowSorter(self.sorter)

        self.scrollPane.getViewport().setView((self.table))
        self.firstTab.add(self.scrollPane, BorderLayout.CENTER)

        # =============================================================================
        # ==================== Second Tab (FIle Upload History v2) ====================
        # =============================================================================

        # Creating second tab
        self.secondTab = JPanel()
        self.secondTab.layout = BorderLayout()
        self.tabbedPane.addTab("File Upload History v2", self.secondTab)

         # ====================== Start Upload Panel + Button ======================

        # Create a panel for the "Start Upload" button, and also a button
        self.startUploadButtonPanel = JPanel()
        self.startUploadButtonPanel.add(JButton("Start Upload", actionPerformed=self.startUpload))
        # Add the panel into third tab
        self.secondTab.add(self.startUploadButtonPanel, BorderLayout.PAGE_START)
       
        # ====================== Table Panel 2 + Scroll Pane =======================
        # Same as Table 1, but try differenct method

        # Creating a UI for table in api mapper tab
        self.tablePanel2 = JPanel()
        self.colNames = ('#', 'URL', 'Method', 'File Path', 'Status Code', 'Length', 'Time')
        self.dataModel = CustomDefaultTableModelHosts(None, self.colNames)
        self.table2 = JTable(self.dataModel)
        self.table2.getTableHeader().setReorderingAllowed(False)
        self.table2.setAutoCreateRowSorter(True)

        # creating a message eitor from burp to show request and reponse
        self.requestViewer = callbacks.createMessageEditor(None, True)
        self.responseViewer = callbacks.createMessageEditor(None, True)

        # Create a scroll pane to hold the table2
        self.scrollPane2 = JScrollPane(self.table2)
        self.scrollPane2.getViewport().setView((self.table2))
        self.sorter2 = TableRowSorter(self.dataModel)
        self.secondTab.add(self.scrollPane2, BorderLayout.CENTER)
        self.table2.setRowSorter(self.sorter2)

        # =========== Split the pane for request, response and inspector ===========
        self.CommentsSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.bottomviewpanel = JPanel()
        #self.SaveTestCasePanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        #self.SaveTestCasePanel.add(JButton("Save TestCases", actionPerformed=self.SaveTestCases))

        # ==== CONTINUE HERE =====

        # =========== Request, Response, Inspector =========== 
        self.editor_view = JTabbedPane()
        self.editor_view.addTab("Request", self.requestViewer.getComponent())
        self.editor_view.addTab("Response", self.responseViewer.getComponent())
        self.editor_view.addTab('Inspector', self.CommentsSplitPane)

         # creating a split in api mapper with split size
        spl = JSplitPane(JSplitPane.VERTICAL_SPLIT)


        # adding the UI for split pane in api mapper tab

       
        spl.setLeftComponent(self.scrollPane2)
        spl.setRightComponent(self.editor_view)

        # adding the spilt part to api mapper tab
        self.secondTab.add(spl)

        # addinG the burp Defalut UI customization for the api mapper tab
        self.callbacks.customizeUiComponent(spl)
        self.callbacks.customizeUiComponent(self.table2)
        self.callbacks.customizeUiComponent(self.scrollPane2)
        self.callbacks.customizeUiComponent(self.editor_view)

        # ====================== MAIN PANEL =========================

        # Add tabs to the tabbedPane
       # self.tabbedPane.addTab("Upload history", self.history_panel)

        # Add tabbedPane to the main_panel
        # East = Right, West = Left, North = Top (same as left), CENTER = same as left, South = Bottom
        self.tab.add(self.tabbedPane, BorderLayout.CENTER)

        # Register the extension
        callbacks.addSuiteTab(self)


    # Only wheb getTabCaption and getUiCoponent are defined, the extension will be added to Burp Suite

    # Returning the tab name to Burp Suite
    def getTabCaption(self):
        return "Files Uploader History"

    # Returning the UI to the extension tab (returning new tab inside extension tab)
    def getUiComponent(self):
        return self.tabbedPane
    
    # Placeholder
    def startUpload(self, event):
        pass

# extending the default table model to remove the editable column from the checklist taB table
class CustomDefaultTableModelHosts(DefaultTableModel):

    # override isCellEditable method
    def isCellEditable(self, row, column):
        return 0


class CustomSelectionListener(ListSelectionListener):
    def __init__(self, table, request_viewer, response_viewer):
        self.table = table
        self.request_viewer = request_viewer
        self.response_viewer = response_viewer

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            selected_row = self.table.getSelectedRow()
            if selected_row != -1:
                request_data = self.table.getValueAt(selected_row, 4)  
                response_data = self.table.getValueAt(selected_row, 5)  
                self.request_viewer.setMessage(request_data, True)
                self.response_viewer.setMessage(response_data, True)