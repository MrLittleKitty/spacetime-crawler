import logging
import sys

from collections import defaultdict

from datamodel.search.EawolfeSantiadmTevinl1_datamodel import EawolfeSantiadmTevinl1Link, \
    OneEawolfeSantiadmTevinl1UnProcessedLink
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter, Getter
from lxml import html, etree
import re, os
from time import time
from uuid import uuid4

from urlparse import urlparse, parse_qs
from uuid import uuid4

logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"


@Producer(EawolfeSantiadmTevinl1Link)
@GetterSetter(OneEawolfeSantiadmTevinl1UnProcessedLink)
class CrawlerFrame(IApplication):
    app_id = "EawolfeSantiadmTevinl1"

    def __init__(self, frame):
        self.app_id = "EawolfeSantiadmTevinl1"
        self.frame = frame

    def initialize(self):
        self.count = 0
        links = self.frame.get_new(OneEawolfeSantiadmTevinl1UnProcessedLink)
        if len(links) > 0:
            print "Resuming from the previous state."
            self.download_links(links)
        else:
            l = EawolfeSantiadmTevinl1Link("http://www.ics.uci.edu/")
            print l.full_url
            self.frame.add(l)

    def update(self):
        unprocessed_links = self.frame.get_new(OneEawolfeSantiadmTevinl1UnProcessedLink)
        if unprocessed_links:
            self.download_links(unprocessed_links)

    def download_links(self, unprocessed_links):
        for link in unprocessed_links:
            print "Got a link to download:", link.full_url
            downloaded = link.download()
            links = extract_next_links(downloaded)
            for l in links:
                if is_valid(l):
                    self.frame.add(EawolfeSantiadmTevinl1Link(l))

    def shutdown(self):
        print (
            "Time time spent this session: ",
            time() - self.starttime, " seconds.")


# Regex to validate absolute URLS was pulled from this gist: https://gist.github.com/uogbuji/705383
URL_REGEX = re.compile(
    ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')

domainMap = defaultdict(lambda: 0)

mostLinks = 0
page = ""


def extract_next_links(rawDataObj):
    outputLinks = []
    '''
    rawDataObj is an object of type UrlResponse declared at L20-30
    datamodel/search/server_datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.
    '''

    url = None
    if rawDataObj.is_redirected:
        url = rawDataObj.final_url
    else:
        url = rawDataObj.url

    parsed = urlparse(url)
    domain = parsed.hostname[0:parsed.hostname.find('.ics.uci.edu')]
    domainMap[domain] = domainMap[domain] + 1

    if rawDataObj.content is not None and rawDataObj.content is not "":
        try:
            # Attempt to parse the content as an html file
            doc = html.fromstring(rawDataObj.content)
            doc.make_links_absolute(url)
            for href in doc.iterlinks():
                if URL_REGEX.match(href[2]):  # Make sure that any link is an absolute address
                    outputLinks.append(processLink(href[2], parsed))
        except:
            # Treat the raw content as a plain text and search for urls in it
            links = re.findall(URL_REGEX, rawDataObj.content)
            for link in links:
                outputLinks.append(processLink(link, parsed))

    global mostLinks
    if len(outputLinks) > mostLinks:
        mostLinks = len(outputLinks)
        global page
        page = url

    return outputLinks


AFG_PAGE = re.compile(r'afg[0-9]+_page_id')
REPLY_TO = re.compile(r'replytocom=[0-9]+')


def processLink(url, parsed):
    # Remove all the query parameters for links from wics that have the AFG page parameter
    if AFG_PAGE.search(url):
        return url[0:url.find('?')]

    if 'replytocom=' in parsed.query:
        return re.sub(REPLY_TO, '', url)

    return url


def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be
    downloaded or not.
    Robot rules and duplication rules are checked separately.
    This is a great place to filter out crawler traps.
    '''
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    try:
        if ".ics.uci.edu" not in parsed.hostname or "calendar.ics.uci.edu" in parsed.hostname \
                or re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
                            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
                            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
                            + "|thmx|mso|arff|rtf|jar|csv" \
                            + "|rm|smil|wmv|swf|wma|zip|rar|gz|pdf|ova)$", parsed.path.lower()):
            return False

        # Stop crawler trap on the WICS site with the afg_page_id query parameter
        if AFG_PAGE.search(parsed.query):
            return False

        if 'replytocom=' in parsed.query:
            return False

        # Word-press JSON apis are a black hole, filter them out
        if 'wp-json' in parsed.path:
            return False

        return True

    except TypeError:
        print ("TypeError for ", parsed)
        return False
