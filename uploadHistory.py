from burp import IBurpExtender, IHttpListener, IHttpRequestResponse

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers() 
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("Hello Extension")
        print("Hello test") # This will show up in "Load Burp extension" window's Output
        callbacks.issueAlert("Hello test 123") # This will show up up Burp Suite Dashboard log

    def getResponseHeadersAndBody(self, content):
        reponse = content.getResponse()
        reponse_data = self._helpers.analyzeResponse(reponse)
        headers = list(reponse_data.getHeaders())
        body = reponse[reponse_data.getBodyOffset():].tostring()
        return headers, body

    def processHttpMessage(self, tool, is_request, content):
        if is_request:
            return
        headers, body = self.getResponseHeadersAndBody(content)

        # modify body
        body = body.replace("Cloud", "Butt")

        new_message = self._helpers.buildHttpMessage(headers, body)
        content.setResponse(new_message)