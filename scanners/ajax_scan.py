#!/usr/bin/env python3

"""
AJAX Spider Scanner from https://github.com/zaproxy/zap-api-python/blob/main/src/zapv2/ajaxSpider.py?
Uses a browser engine to crawl JavaScript-heavy web applicatations.
It dynamically interacts with pages, clicking on elements, submitting forms, and executing scripts to discover
URLs and content that a traditional spider might miss.
"""

import os
import six
import time
API_KEY = os.getenv("ZAP_API_KEY", "")

class ajax_scan(object):

    def __init__(self, zap):
        self.zap = zap

    @property
    def allowed_resources(self):
        """
        Gets the allowed resources. The allowed resources are always fetched even if out of scope, allowing to include necessary resources (e.g. scripts) from 3rd-parties.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/allowedResources/')))

    def excluded_elements(self, contextname):
        """
        Gets the excluded elements. The excluded elements are not clicked during crawling, for example, to prevent logging out.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/excludedElements/', {'contextName': contextname})))

    @property
    def status(self):
        """
        Gets the current status of the crawler. Actual values are Stopped and Running.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/status/')))

    def results(self, start=None, count=None):
        """
        Gets the current results of the crawler.
        This component is optional and therefore the API will only work if it is installed
        """
        params = {}
        if start is not None:
            params['start'] = start
        if count is not None:
            params['count'] = count
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/results/', params)))

    @property
    def number_of_results(self):
        """
        Gets the number of resources found.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/numberOfResults/')))

    @property
    def full_results(self):
        """
        Gets the full crawled content detected by the AJAX Spider. Returns a set of values based on 'inScope' URLs, 'outOfScope' URLs, and 'errors' encountered during the last/current run of the AJAX Spider.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/fullResults/')))

    @property
    def option_browser_id(self):
        """
        Gets the configured browser to use for crawling.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionBrowserId/')))

    @property
    def option_event_wait(self):
        """
        Gets the time to wait after an event (in milliseconds). For example: the wait delay after the cursor hovers over an element, in order for a menu to display, etc.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionEventWait/')))

    @property
    def option_max_crawl_depth(self):
        """
        Gets the configured value for the max crawl depth.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionMaxCrawlDepth/')))

    @property
    def option_max_crawl_states(self):
        """
        Gets the configured value for the maximum crawl states allowed.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionMaxCrawlStates/')))

    @property
    def option_max_duration(self):
        """
        Gets the configured max duration of the crawl, the value is in minutes.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionMaxDuration/')))

    @property
    def option_number_of_browsers(self):
        """
        Gets the configured number of browsers to be used.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionNumberOfBrowsers/')))

    @property
    def option_reload_wait(self):
        """
        Gets the configured time to wait after reloading the page, this value is in milliseconds.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionReloadWait/')))

    @property
    def option_click_default_elems(self):
        """
        Gets the configured value for 'Click Default Elements Only', HTML elements such as 'a', 'button', 'input', all associated with some action or links on the page.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionClickDefaultElems/')))

    @property
    def option_click_elems_once(self):
        """
        Gets the value configured for the AJAX Spider to know if it should click on the elements only once.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionClickElemsOnce/')))

    @property
    def option_enable_extensions(self):
        """
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionEnableExtensions/')))

    @property
    def option_random_inputs(self):
        """
        Gets if the AJAX Spider will use random values in form fields when crawling, if set to true.
        This component is optional and therefore the API will only work if it is installed
        """
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/view/optionRandomInputs/')))

    def scan(self, url=None, inscope=None, contextname=None, subtreeonly=None, apikey = None):
        """
        Runs the AJAX Spider against a given target.
        This component is optional and therefore the API will only work if it is installed
        """

        # Load the API key
        apikey = apikey or API_KEY

        #Build the request parameters
        params = {}
        if url is not None:
            params['url'] = url
        if inscope is not None:
            params['inScope'] = inscope
        if contextname is not None:
            params['contextName'] = contextname
        if subtreeonly is not None:
            params['subtreeOnly'] = subtreeonly

        # Add the API key to the parameters
        if apikey:
            params['apikey'] = apikey

        #Send the request to ZAP
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/scan/', params)))
    

    def scan_as_user(self, contextname, username, url=None, subtreeonly=None, apikey=None):
        """Runs the AJAX Spider from the perspective of a User of the web application.
        """
        apikey = apikey or API_KEY
        params = {'contextName': contextname, 'userName': username}
        if url is not None:
                params['url'] = url
        if subtreeonly is not None:
            params['subtreeOnly'] = subtreeonly
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/scanAsUser/', params)))


    def stop(self, apikey=None):
        """Stops the AJAX Spider."""
        apikey = apikey or API_KEY
        params = {}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/stop/', params)))


    def add_allowed_resource(self, regex, enabled=None, apikey=None):
        """Adds an allowed resource."""
        apikey = apikey or API_KEY
        params = {'regex': regex}
        if enabled is not None:
            params['enabled'] = enabled
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/addAllowedResource/', params)))


    def add_excluded_element(self, contextname, description, element, xpath=None, text=None, attributename=None, attributevalue=None, enabled=None, apikey=None):
        """Adds an excluded element to a context."""
        apikey = apikey or API_KEY
        params = {'contextName': contextname, 'description': description, 'element': element}
        if xpath is not None:
            params['xpath'] = xpath
        if text is not None:
            params['text'] = text
        if attributename is not None:
            params['attributeName'] = attributename
        if attributevalue is not None:
            params['attributeValue'] = attributevalue
        if enabled is not None:
            params['enabled'] = enabled
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/addExcludedElement/', params)))


    def modify_excluded_element(self, contextname, description, element, descriptionnew=None, xpath=None, text=None, attributename=None, attributevalue=None, enabled=None, apikey=None):
        """Modifies an excluded element of a context."""
        apikey = apikey or API_KEY
        params = {'contextName': contextname, 'description': description, 'element': element}
        if descriptionnew is not None:
            params['descriptionNew'] = descriptionnew
        if xpath is not None:
            params['xpath'] = xpath
        if text is not None:
            params['text'] = text
        if attributename is not None:
            params['attributeName'] = attributename
        if attributevalue is not None:
            params['attributeValue'] = attributevalue
        if enabled is not None:
            params['enabled'] = enabled
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/modifyExcludedElement/', params)))


    def remove_excluded_element(self, contextname, description, apikey=None):
        """Removes an excluded element from a context."""
        apikey = apikey or API_KEY
        params = {'contextName': contextname, 'description': description}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/removeExcludedElement/', params)))


    def remove_allowed_resource(self, regex, apikey=None):
        """Removes an allowed resource."""
        apikey = apikey or API_KEY
        params = {'regex': regex}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/removeAllowedResource/', params)))


    def set_enabled_allowed_resource(self, regex, enabled, apikey=None):
        """Sets whether or not an allowed resource is enabled."""
        apikey = apikey or API_KEY
        params = {'regex': regex, 'enabled': enabled}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setEnabledAllowedResource/', params)))


    def set_option_browser_id(self, string, apikey=None):
        """Sets the configuration of the AJAX Spider to use one of the supported browsers."""
        apikey = apikey or API_KEY
        params = {'String': string}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionBrowserId/', params)))


    def set_option_click_default_elems(self, boolean, apikey=None):
        """Sets whether or not the AJAX Spider will only click on the default HTML elements."""
        apikey = apikey or API_KEY
        params = {'Boolean': boolean}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionClickDefaultElems/', params)))


    def set_option_click_elems_once(self, boolean, apikey=None):
        """When enabled, the crawler attempts to interact with each element only once."""
        apikey = apikey or API_KEY
        params = {'Boolean': boolean}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionClickElemsOnce/', params)))


    def set_option_enable_extensions(self, boolean, apikey=None):
        """Enables or disables browser extensions for the AJAX Spider."""
        apikey = apikey or API_KEY
        params = {'Boolean': boolean}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionEnableExtensions/', params)))


    def set_option_event_wait(self, integer, apikey=None):
        """Sets the time to wait after an event (in ms)."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionEventWait/', params)))


    def set_option_max_crawl_depth(self, integer, apikey=None):
        """Sets the maximum crawl depth."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionMaxCrawlDepth/', params)))


    def set_option_max_crawl_states(self, integer, apikey=None):
        """Sets the maximum number of crawl states."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionMaxCrawlStates/', params)))


    def set_option_max_duration(self, integer, apikey=None):
        """Sets the maximum crawl duration (in minutes)."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionMaxDuration/', params)))


    def set_option_number_of_browsers(self, integer, apikey=None):
        """Sets the number of browsers to use."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionNumberOfBrowsers/', params)))


    def set_option_random_inputs(self, boolean, apikey=None):
        """When enabled, inserts random values into form fields."""
        apikey = apikey or API_KEY
        params = {'Boolean': boolean}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionRandomInputs/', params)))


    def set_option_reload_wait(self, integer, apikey=None):
        """Sets the wait time after a page reload (in ms)."""
        apikey = apikey or API_KEY
        params = {'Integer': integer}
        if apikey:
            params['apikey'] = apikey
        return six.next(six.itervalues(self.zap._request(self.zap.base + 'ajaxSpider/action/setOptionReloadWait/', params)))
    

# AJAX Spider helper
# Adds: run_ajax(zap, target, *, poll=3)
# Uses zap.ajaxSpider.* so it works with the official API and existing class.

def run_ajax(zap, target, *, poll=3):
    try:
        print(f"[+] AJAX spider starting: {target}")
        zap.ajaxSpider.scan(target)
        while True:
            status = str(zap.ajaxSpider.status).lower()  # property in many builds
            print(f"\rAJAX spider status: {status}", end="", flush=True)
            if status == "stopped":
                break
            time.sleep(poll)
        print("\n[+] AJAX spider complete.")
    except Exception as e:
        print(f"\n[~] AJAX spider skipped or failed: {e}")
