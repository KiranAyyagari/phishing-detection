import base64
import datetime
import logging
import os
import pickle
import string
import xml.etree.ElementTree as ET
from subprocess import *
from urllib.parse import urlparse

import dotenv
import favicon
import numpy as np
import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv

load_dotenv(dotenv.find_dotenv())
logging.basicConfig(level=logging.INFO)
logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')


def find_ip_address(url):
    index = url.find('://')
    url = url[index + 3:]
    ip_address = url.split('/')[0]
    ip_address = ip_address.replace(".", "")
    counter_hexdigits = 0
    for ip in ip_address:
        if ip in string.hexdigits or ip == 'x':
            counter_hexdigits += 1
    total_length = len(ip_address)
    have_ip_address = 1
    if counter_hexdigits >= total_length:
        have_ip_address = -1
        logging.info("Url consists of IP Address")
    return have_ip_address


def find_url_length(url):
    url_length = 1
    if len(url) > 75:
        url_length = -1
        logging.info("The length of url is greater than 75")
    elif len(url) >= 54 or len(url) <= 75:
        url_length = 0
        logging.info("The length of url is in between 54 and 75")
    return url_length


def get_complete_url(shortened_url):
    command_stdout = Popen(['curl', shortened_url], stdout=PIPE).communicate()[0]
    output = command_stdout.decode('utf-8')
    href_index = output.find("href=")
    if href_index == -1:
        href_index = output.find("HREF=")
    splitted_ = output[href_index:].split('"')
    expanded_url = splitted_[1]
    logging.info("The complete url is {}".format(expanded_url))
    return expanded_url


def check_for_shortened_url(url):
    famous_short_urls = ["bit.ly", "tinyurl.com", "goo.gl",
                         "rebrand.ly", "t.co", "youtu.be",
                         "ow.ly", "w.wiki", "is.gd"]

    domain_of_url = url.split("://")[1]
    domain_of_url = domain_of_url.split("/")[0]
    status = 1
    if domain_of_url in famous_short_urls:
        status = -1
        logging.info("The domain of url is one of  {}".format(famous_short_urls))

    complete_url = None
    if status == -1:
        complete_url = get_complete_url(url)

    return status, complete_url


def find_at_symbol(url):
    have_at_symbol = 1
    index = url.find("@")
    if index != -1:
        have_at_symbol = -1
        logging.info("Url contains @")

    return have_at_symbol


def find_redirect(url):
    have_redirect = 1
    index = url.find("://")
    split_url = url[index + 3:]
    index = split_url.find('//')
    if index != -1:
        have_redirect = -1
        logging.info("Url contains redirect")
    return have_redirect


def find_prefix(url):
    have_prefix = 1
    index = url.find("://")
    split_url = url[index + 3:]
    index = split_url.find("/")
    split_url = url[:index]
    index = split_url.find('-')
    if index != -1:
        have_prefix = -1
        logging.info("Url contains '-' in domain")
    return have_prefix


def find_multi_subdomains(url):
    have_multi_subdomains = 1
    index = url.find("://")
    split_url = url[index + 3:]
    index = split_url.find("/")
    split_url = split_url[:index]
    index = split_url.find("www.")
    split_url = split_url[index + 4:]
    counter_multi_subdomain = 0
    for i in split_url:
        if i == '.':
            counter_multi_subdomain += 1

    if counter_multi_subdomain == 2:
        have_multi_subdomains = 0
        logging.info("Url contains two sub domains")
    elif counter_multi_subdomain > 2:
        have_multi_subdomains = -1
        logging.info("Url contains multiple sub domains")

    return have_multi_subdomains


def find_authority(url):
    index_https = url.find("https://")
    valid_auth = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign", "LinkedIn",
                  "Sectigo",
                  "Symantec", "DigiCert", "Network Solutions", "RapidSSLonline", "SSL.com", "Entrust Datacard",
                  "Google", "Facebook"]

    cmd = "curl -vvI " + url

    stdout = Popen(cmd, shell=True, stderr=PIPE, env={}).stderr
    output = stdout.read()
    std_out = output.decode('UTF-8')
    index = std_out.find("O=")

    split = std_out[index + 2:]
    index_sp = split.find(" ")
    cur = split[:index_sp]

    index_sp = cur.find(",")
    if index_sp != -1:
        cur = cur[:index_sp]
    label = -1
    if cur in valid_auth and index_https != -1:
        label = 1
        logging.info("Url contains valid authority")
    else:
        logging.info("Url contains invalid authority")
    return label


def domain_registration(url):
    extract_res = tldextract.extract(url)
    ul = extract_res.domain + "." + extract_res.suffix
    try:
        wres = whois.whois(url)
        f = wres["Creation Date"][0]
        s = wres["Registry Expiry Date"][0]
        if s > f + relativedelta(months=+12):
            logging.info("Domain is valid and not expired")
            return 1
        else:
            logging.info("Domain is not valid and expired")
            return -1
    except Exception as exc:
        logging.error("Exception occurred while fetching the domain information")
        return -1


def check_favicon(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain
    try:
        favs = favicon.get(url)
        match = 0
        for favi in favs:
            url2 = favi.url
            extract_res = tldextract.extract(url2)
            url_ref2 = extract_res.domain

            if url_ref in url_ref2:
                match += 1

        if match >= len(favs) / 2:
            logging.info("Favicons are from same domain of url mostly")
            return 1
        logging.info("Favicons are not from same domain")
        return -1
    except Exception as exc:
        logging.error("Exception while fetching favicon info: ")
        return -1


def find_token(url):
    ix = url.find("//https")
    if ix == -1:
        logging.info("//https is not present in url")
        return 1
    else:
        logging.info("//https is  present in url")
        return -1


def check_request_url(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain
    command_stdout = Popen(['curl', 'https://api.hackertarget.com/pagelinks/?q=' + url], stdout=PIPE).communicate()[0]
    links = command_stdout.decode('utf-8').split("\n")
    count = 0

    for link in links:
        extract_res = tldextract.extract(link)
        url_ref2 = extract_res.domain
        url_ref2_subdomain = extract_res.subdomain
        if url_ref not in url_ref2 \
                and url_ref not in url_ref2_subdomain:
            count += 1

    count /= len(links)

    if count < 0.22:
        logging.info("22% of href domains are not from same domain of Url")
        return 1
    elif count < 0.61:
        logging.info("61% of href domains are not from same domain of Url")
        return 0
    else:
        logging.info("More than 61% of href domains are not from same domain of Url")
        return -1


def url_validator(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except Exception as exc:
        logging.error("Exception while parsing the url: ")
        return False


def check_url_of_anchor(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain
    try:
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, "xml")
        a_tags = soup.find_all('a')

        if len(a_tags) == 0:
            logging.info("This url doesn't contains anchor tags")
            return 1

        invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
        bad_count = 0
    except Exception as exc:
        logging.error("Exception occurred while fetching the anchor tags: ")
        return -1
    try:
        for t in a_tags:
            link = t['href']

            if link in invalid:
                bad_count += 1

            if url_validator(link):
                extract_res = tldextract.extract(link)
                url_ref2 = extract_res.domain

                if url_ref not in url_ref2:
                    bad_count += 1
    except Exception as exc:
        logging.error("Exception occurred while fetching href: ")

    bad_count /= len(a_tags)

    if bad_count < 0.31:
        logging.info("Less than 31% anchors present for url")
        return 1
    elif bad_count <= 0.67:
        logging.info("In between 31% and 67% anchors present for url")
        return 0
    else:
        logging.info("More than 67% anchors present for url")
    return -1


def tags(url):
    try:
        html_dom = requests.get(url).text
        soup = BeautifulSoup(html_dom, "xml")
        meta_tags = soup.find_all('Meta')
        url_domain = tldextract.extract(url)
        meta_count = 0
        for tag in meta_tags:
            href_link = tag['href']
            page = tldextract.extract(href_link)
            page_domain = page.domain
            if page not in page_domain:
                meta_count += 1
        script_tag_count = 0
        script_tags = soup.find_all('Script')
        for script_tag in script_tags:
            href_link = script_tag['href']
            page = tldextract.extract(href_link)
            page_domain = page.domain
            if page not in page_domain:
                script_tag_count += 1
        link_count = 0
        link_tags = soup.find_all('Link')
        for k in link_tags:
            href_link = k['href']
            page = tldextract.extract(href_link)
            page_domain = page.domain
            if page not in page_domain:
                link_count += 1
        percent_mtag = 0
        percent_stag = 0
        percent_ltag = 0

        if len(meta_tags) != 0:
            percent_mtag = (meta_count * 100) // len(meta_tags)
        if len(script_tags) != 0:
            percent_stag = (script_tag_count * 100) // len(script_tags)
        if len(link_tags) != 0:
            percent_ltag = (link_count * 100) // len(link_tags)

        if percent_mtag + percent_stag + percent_ltag < 17:
            logging.info("Less than 17% of meta tags, script tags and link tags are present")
            return 1
        elif percent_mtag + percent_stag + percent_ltag <= 81:
            logging.info("In between 17%  and 81% , meta tags, script tags and link tags are present")
            return 0
        logging.info("More than 81% , meta tags, script tags and link tags are present")
        return -1
    except Exception as exc:
        logging.error("Exception occurred while fetching tags: ")
        return -1


def sfh(url):
    try:
        html_dom = requests.get(url).text
        soup = BeautifulSoup(html_dom, "xml")
        try:
            form = str(soup.form)
            action = form.find("action")
            if action != -1:
                gtr = form[action:].find(">")
                abt_blank = form[action + 8:gtr - 1]
                if abt_blank == "" or abt_blank == "about:blank":
                    logging.info("'about:blank' is present in URL")
                    return -1
                extracted_url = tldextract.extract(url)
                domain = extracted_url.domain
                abt_blank_url = tldextract.extract(abt_blank)
                abt_blank_domain = abt_blank_url.domain
                if domain in abt_blank_domain:
                    logging.info("Url and 'about:blank' domain are same")
                    return 1
                return 0
            else:
                return 1
        except Exception as exc:
            logging.error("Exception occurred while fetching domain: ")
            return 1
    except Exception as exc:
        logging.error("Exception occurred while fetching dom: ")
        return -1


def check_submit_to_email(url):
    try:
        html_dom = requests.get(url).text
        soup = BeautifulSoup(html_dom, "xml")
        form = str(soup.form)
        index = form.find('mail()')

        if index == -1:
            index = form.find('mailto:')

        if index == -1:
            logging.info("mail() and mailto: are not present in dom")
            return 1
        else:
            logging.info("mail() and mailto: are present in dom")
        return -1
    except Exception as exc:
        logging.error("Exception occurred while fetching dom: ")
        return -1


def redirect(url):
    try:
        extracted_url = tldextract.extract(url)
        domain = extracted_url.domain
        cmd = "curl -sILk " + domain + "| egrep 'HTTP|Loc' | sed 's/Loc/ -> Loc/g'"
        stdout = Popen(cmd, shell=True, stderr=PIPE, env={}).stderr
        output = stdout.read()
        opt = output.decode('UTF-8')
        opt = opt.split("\n")

        new_links = []
        for line in opt:
            line = line.replace("\r", " ")
            new_links.extend(line.split(" "))

        count = 0
        for line in new_links:

            if line.isdigit():
                conv = int(line)
                if 300 < conv < 310:
                    count += 1

        last_url = None
        for line in new_links[::-1]:
            if url_validator(line):
                last_url = line
                break

        if count <= 1:
            logging.info("Redirection is less than or equal to 1 ")
            return 1, last_url
        elif 2 <= count < 4:
            logging.info("Redirection is atleast 4 times ")
            return 0, last_url
        else:
            logging.info("Redirection is more than 4 times ")
        return -1, last_url
    except Exception as exc:
        logging.error("Exception occurred while fetching redirect link: ")
        return -1, ""


def check_on_mouseover(url):
    try:
        html_content = requests.get(url).text
    except Exception as exc:
        logging.error("Exception occured when extracting html: ")
        return -1
    soup = BeautifulSoup(html_content, "xml")
    if str(soup).lower().find('onmouseover="window.status') != -1:
        logging.info("Html dom contains mouseover function")
        return -1
    logging.info("Html dom doesn't contain mouseover function")
    return 1


def check_right_click(url):
    try:
        html = requests.get(url).text
    except Exception as exc:
        logging.error("Exception occurred while fetching the html: ")
        return -1
    soup = BeautifulSoup(html, "xml")
    if str(soup).lower().find('check_onmouseover') != -1:
        return -1
    elif str(soup).lower().find("preventdefault()") != -1:
        return -1
    elif str(soup).lower().find("event.button == 2") != -1:
        return -1
    return 1


def check_iframe(url):
    try:
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, "xml")
        if str(soup.iframe).lower().find("frameborder") == -1:
            logging.info("Html doesn't contain iframe")
            return 1
        logging.info("Html contains iframe")
        return -1
    except Exception as exc:
        logging.error("Exception occurred while fetching html: ")
        return -1


def check_age_of_domain(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
        whois_res = whois.whois(url)
        if isinstance(whois_res["creation_date"], list) and datetime.datetime.now() > (
                whois_res["creation_date"][0] + relativedelta(months=+6)):
            logging.info("Domain is not expired")
            return 1
        elif isinstance(whois_res["creation_date"], datetime.datetime) and datetime.datetime.now() > (
                whois_res["creation_date"] + relativedelta(months=+6)):
            logging.info("Domain is not expired")
            return 1
        else:
            logging.info("Domain is  expired")
            return -1
    except Exception as exc:
        logging.error("Exception occurred while fetching the domain info: ")
        return -1


def check_dns_record(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
        whois_res = whois.whois(url)
        logging.info("Dns record is valid")
        return 1
    except Exception as exc:
        logging.error("Dns record is invalid")
        return -1


def check_web_traffic(url):
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
        html_content = requests.get("https://www.alexa.com/siteinfo/" + url_ref).text
        soup = BeautifulSoup(html_content, "xml")
        value = str(soup.find('div', {'class': "rankmini-rank"}))[42:].split("\n")[0].replace(",", "")

        if not value.isdigit():
            logging.info("No rank available for the website")
            return -1

        value = int(value)
        if value < 100000:
            logging.info("Rank for the website - {}".format(value))
            return 1
        logging.info("Rank for the website - {}".format(value))
        return 0
    except Exception as exc:
        logging.error("Exception occurred while fetching the web traffic: ")
        return -1


def get_pagerank(url):
    key = os.getenv('OPEN_PAGE_RANK_API_KEY')
    openpagerank_url = os.getenv('OPEN_PAGE_RANK_URL')
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    headers = {'API-OPR': key}
    domain = url_ref
    req_url = openpagerank_url + domain
    try:
        request = requests.get(req_url, headers=headers)
        result = request.json()
        value = result['response'][0]['page_rank_decimal']
        if type(value) == str:
            value = 0

        if value < 2:
            logging.info("Page rank is {}".format(value))
            return -1
        logging.info("Page rank is {}".format(value))
        return 1
    except Exception as exc:
        logging.error("Exception occurred while fetching the page rank: ")
        return -1


def check_statistical_report(url):
    headers = {
        'format': 'json',
    }

    def get_url_with_ip(URI):
        """Returns url with added URI for request"""
        phishtank_url = os.getenv('PHISHTANK_URL')
        new_check_bytes = URI.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        phishtank_url += base64_new_check
        return phishtank_url

    def send_the_request_to_phish_tank(url, headers):
        """This function sends a request."""
        response = requests.request("POST", url=url, headers=headers)
        return response

    url = get_url_with_ip(url)
    r = send_the_request_to_phish_tank(url, headers)

    def parseXML(xmlfile):
        try:
            root = ET.fromstring(xmlfile)
            verified = False
            for item in root.iter('verified'):
                if item.text == "true":
                    verified = True
                    break

            phishing = False
            if verified:
                for item in root.iter('valid'):
                    if item.text == "true":
                        phishing = True
                        break

            return phishing
        except Exception as exc:
            logging.error("Exception occurred while fetching statistical report: ")
            return True

    inphTank = parseXML(r.text)

    if inphTank:
        logging.info("This Url might be Phishing Url ")
        return -1
    logging.info("This Url is valid")
    return 1


def extract_features(url):
    logging.info("Extracting features from Url")
    features_extracted = [0] * 25
    phStatus, expanded = check_for_shortened_url(url)
    features_extracted[2] = phStatus
    phStatus, last_url = redirect(url)
    features_extracted[16] = phStatus
    if expanded is not None:
        if len(expanded) >= len(url):
            url = expanded

    if last_url is not None:
        if len(last_url) > len(url):
            url = last_url
    features_extracted[0] = find_ip_address(url)
    features_extracted[1] = find_url_length(url)
    features_extracted[3] = find_at_symbol(url)
    features_extracted[4] = find_redirect(url)
    features_extracted[5] = find_prefix(url)
    features_extracted[6] = find_multi_subdomains(url)
    features_extracted[7] = find_authority(url)
    features_extracted[8] = domain_registration(url)
    features_extracted[9] = check_favicon(url)
    features_extracted[10] = find_token(url)
    features_extracted[11] = check_request_url(url)
    features_extracted[12] = check_url_of_anchor(url)
    features_extracted[13] = tags(url)
    features_extracted[14] = sfh(url)
    features_extracted[15] = check_submit_to_email(url)
    features_extracted[17] = check_on_mouseover(url)
    features_extracted[18] = check_right_click(url)
    features_extracted[19] = check_iframe(url)
    features_extracted[20] = check_age_of_domain(url)
    features_extracted[21] = check_dns_record(url)
    features_extracted[22] = check_web_traffic(url)
    features_extracted[23] = get_pagerank(url)
    features_extracted[24] = check_statistical_report(url)
    logging.info("Feature extraction from Url is done")
    return features_extracted


def convertEncodingToPositive(data):
    logging.info("Encode the negative to positive values")
    mapping = {-1: 2, 0: 0, 1: 1}
    i = 0
    for value in data:
        data[i] = mapping[value]
        i += 1
    logging.info("Encoding negative values to positive is done")
    return data


def predict(url):
    features_extracted = extract_features(url)
    features_extracted = convertEncodingToPositive(features_extracted)
    one_hot_enc = pickle.load(open("model/One_Hot_Encoder_New", "rb"))
    logging.info("One Hot Encoder is loaded successfully")
    transformed_point = one_hot_enc.transform(np.array(features_extracted).reshape(1, -1))
    logging.info("Features are encoded using One Hot Encoder")
    model = pickle.load(open("model/SVM_Final_Model_New", "rb"))
    logging.info("Model is loaded successfully")
    status = model.predict(transformed_point)
    logging.info("Prediction is done")
    return status


if __name__ == "__main__":
    print("Website is ", predict("http://u1047531.cp.regruhosting.ru/acces-inges-20200104-t452/3facd"))
