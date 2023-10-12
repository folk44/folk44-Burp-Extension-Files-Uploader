from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTabbedPane, JButton, JFileChooser, JList, JScrollPane, DefaultListModel, JTextArea, JLabel, BoxLayout, JFrame, SwingUtilities
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

        # Add create history panel in Jpanel() using GridLayout() format
        self.history_panel = JPanel() 
        self.history_panel.setLayout(GridLayout(4,4)) # GridLayout(rows, columns)

        k = 0

        for i in range(1,5):
            for j in range(1,5):
                k = k + 1
                self.history_panel.add(JButton("Grid " + str(k)))

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