import requests
import os
import json
import re
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TIMEOUT=3
social_list = {
    'instagram.com': '',
    'github.com': '',
    'facebook.com': '',
    'vk.com': '',
    'twitter.com': ''
}


ports = os.environ.get('PORTS')
vuln_id = os.environ.get('VULN_ID')
urls = ['http://{0}/'.format(os.environ.get('DOMAIN'))]
try:
    ports = ports.strip(' ').split(',')
    for port in ports:
        urls.append('http://{0}:{1}/'.format(os.environ.get('DOMAIN'), port))
except Exception as ex:
    pass


def resp(url, state=False):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


def parse_social_networks(text):
    links_list = []
    if not any([text.find(social) for social in social_list]) > -1:
        return links_list
    for social in social_list:
        findings = re.findall(fr'(?:{social}/)(\w+)', text)
        if findings:
            links_list.append({social: findings[0]})
    return links_list


def check_social_404(links):
    result_list = []
    if len(links) == 0:
        return result_list
    for link in links:
        for social, nickname in link.items():
            social_url = f'https://{social}/{nickname}'
            if 'twitter' in social:
                social_url = f'https://mobile.{social}/{nickname}'
            if requests.get(social_url).status_code == 404:
                result_list.append(social)
    return result_list


def check():
    if not urls:
        return resp(False)
    for url in urls:
        try:
            page_content = requests.get(url, timeout=TIMEOUT, verify=False).text
            links = parse_social_networks(page_content)
            result = check_social_404(links)
            if len(result) > 0:
                resp(url=url, state=True)
        except Exception as ex:
            pass
    return resp(url=url, state=False)


if __name__ == '__main__':
    print(check())