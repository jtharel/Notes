from burp import IBurpExtender, IHttpListener
from java.net import URLEncoder
from java.util import HashMap
import time
import hmac
import hashlib
import base64
import urllib  # Used for correct percent encoding

class BurpExtender(IBurpExtender, IHttpListener):
    def __init__(self):
        self.consumer_key = "YOUR_CONSUMER_KEY"
        self.consumer_secret = "YOUR_CONSUMER_SECRET"
        self.access_token = "YOUR_ACCESS_TOKEN"
        self.access_token_secret = "YOUR_ACCESS_TOKEN_SECRET"
        self.oauth_version = "1.0"
        self.oauth_signature_method = "HMAC-SHA1"
 
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Jimmy GET OAuth Extension v1.1")
        self.callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, tool_flag, message_is_request, request_response):
        if message_is_request:
            try:
                # Generate new nonce and timestamp
                self.oauth_nonce = str(int(time.time() * 1000))
                self.oauth_timestamp = str(int(time.time()))
                request_info = self.helpers.analyzeRequest(request_response)

                # Extract the original URL and split into base path and query
                original_url = request_info.getUrl().toString()
                url_parts = original_url.split('?')
                base_url = url_parts[0]  # e.g., https://example.com/api/resource
                path = '/' + '/'.join(base_url.split('/')[3:])  # Extract the URL path
                self.callbacks.printOutput("Extracted Path: " + path)

                # Ignore the original query and use only updated OAuth parameters
                query_dict = HashMap()  # Start with an empty query dictionary

                # Generate new OAuth parameters
                oauth_params = self.create_oauth_params(base_url, query_dict)

                # Rebuild the query string with updated OAuth parameters
                updated_query = self.build_query_string(oauth_params)

                # Construct the updated request line (path + query string)
                final_path_and_query = path + ("?" + updated_query if updated_query else "")
                self.callbacks.printOutput("Final Path and Query: " + final_path_and_query)

                # Modify the first header (request line) to include the updated path and query
                headers = list(request_info.getHeaders())
                headers[0] = "GET %s HTTP/1.1" % final_path_and_query

                # Rebuild the request with updated headers and an empty body
                updated_request = self.helpers.buildHttpMessage(headers, None)
                request_response.setRequest(updated_request)

                # Log the final outgoing request
                final_request_bytes = request_response.getRequest()
                final_request_str = ''.join(chr(x) for x in final_request_bytes)
                self.callbacks.printOutput("Final Outgoing Request Sent to Server:")
                self.callbacks.printOutput(final_request_str)
                self.callbacks.printOutput("-----------")

            except Exception as e:
                self.callbacks.printError("Error in processHttpMessage: %s" % str(e))

    def parse_query_string(self, query_string):
        """
        Parse the query string into a dictionary.
        """
        query_dict = HashMap()
        if query_string:
            params = query_string.split("&")
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    query_dict.put(key, value)
        return query_dict

    def build_query_string(self, oauth_params):
        """
        Construct the query string using only the OAuth parameters.
        """
        query_list = []

        # Add OAuth parameters in their specific order
        oauth_order = [
            "oauth_consumer_key",
            "oauth_token",
            "oauth_signature_method",
            "oauth_timestamp",
            "oauth_nonce", 
            "oauth_version"
        ]
        for key in oauth_order:
            if oauth_params.containsKey(key):
                query_list.append("%s=%s" % (URLEncoder.encode(key, "UTF-8"), URLEncoder.encode(oauth_params.get(key), "UTF-8")))

        # Add the OAuth signature
        query_list.append("oauth_signature=%s" % URLEncoder.encode(oauth_params.get("oauth_signature"), "UTF-8"))

        return "&".join(query_list)

    def create_oauth_params(self, base_url, query_dict):
        """
        Create new OAuth parameters, including generating the signature.
        """
        oauth_params = HashMap()
        oauth_params.put("oauth_consumer_key", self.consumer_key)
        oauth_params.put("oauth_nonce", self.oauth_nonce)
        oauth_params.put("oauth_signature_method", self.oauth_signature_method)
        oauth_params.put("oauth_timestamp", self.oauth_timestamp)
        oauth_params.put("oauth_token", self.access_token)
        oauth_params.put("oauth_version", self.oauth_version)

        # Create the signature base string and generate the signature
        signature_base_string = self.create_signature_base_string(base_url, query_dict, oauth_params)
        signature = self.generate_oauth_signature(signature_base_string)
        oauth_params.put("oauth_signature", signature)

        return oauth_params

    def create_signature_base_string(self, base_url, query_dict, oauth_params):
        """
        Generate the signature base string for signing OAuth parameters.
        """
        # Remove default ports (:443 and :80) from the base URL
        if base_url.startswith("https://") and ":443" in base_url:
            base_url = base_url.replace(":443", "")
        elif base_url.startswith("http://") and ":80" in base_url:
            base_url = base_url.replace(":80", "")

        # Combine query parameters and OAuth parameters into one dictionary
        all_params = {}
        for entry in query_dict.entrySet():
            all_params[entry.getKey()] = entry.getValue()

        for key, value in oauth_params.items():
            all_params[key] = value

        # Sort and encode the parameters
        sorted_params = sorted(all_params.items())
        encoded_params = [self.percent_encode(key) + "=" + self.percent_encode(value) for key, value in sorted_params]
        query_string = "&".join(encoded_params)

        # Construct the signature base string
        signature_base_string = "GET&" + self.percent_encode(base_url) + "&" + self.percent_encode(query_string)
        self.callbacks.printOutput("Signature Base String: " + signature_base_string)

        return signature_base_string

    def generate_oauth_signature(self, signature_base_string):
        """
        Generate the HMAC-SHA1 signature for the given signature base string.
        """
        key = "%s&%s" % (self.percent_encode(self.consumer_secret), self.percent_encode(self.access_token_secret))
        signature = hmac.new(key.encode("utf-8"), signature_base_string.encode("utf-8"), hashlib.sha1)
        encoded_signature = base64.b64encode(signature.digest()).decode("utf-8")
        self.callbacks.printOutput("Generated OAuth Signature: " + encoded_signature)
        return encoded_signature

    def percent_encode(self, value):
        """
        Correctly percent-encode values for OAuth 1.0a.
        """
        return urllib.quote(value, safe="~")

