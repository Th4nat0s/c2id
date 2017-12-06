#!/usr/bin/env python3
# coding=utf-8

import sys
import yaml
from os import listdir
from os.path import isfile, join
import requests
import hashlib

debug = False

def get(uri):
    # print (uri)
    headers = requests.utils.default_headers()
    headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
    try:
        r = requests.get(uri, timeout=15, headers=headers)
    except requests.exceptions.MissingSchema:
        print('Warning : Invalid Scheme')
        return 000, ""
    except:
        return 000, ""
    return r.status_code, r.content, r.text


# Functions
def getparam(count):
    """Retrieve the parameters appended """
    if len(sys.argv) != count + 1:
        print('C2ID')
        print('To Use: %s http://suspected_uri' % sys.argv[0])
        sys.exit(1)
    else:
        return sys.argv[1]


def load_conf():
    '''load the configuration
    '''
    path = "."
    conf = {}
    conf_files = [f for f in listdir(path) if (isfile(join(path, f)) and f.endswith('.yaml'))]
    for conf_file in conf_files:
        with open(conf_file, 'r') as stream:
            try:
                obj=(yaml.load(stream))
                conf[obj.get('name')] = obj
            except:
                print("! Yaml syntax error in %s" % conf_file)
    # print (conf)
    return(conf)


def page2folder(arg):
    """
    Remove a page from an uri

    args:
        arg (str) string
    return
        str, str
    """
    if arg.endswith("/"):
        return arg, None
    args = arg.split("/")

    if "." in args[-1]:
        ext = args[-1].split('.')[1]  # récupère l'extention
        if ext.lower() in ['php', 'html', 'pl', 'htm', 'aspx']:
            return "/".join(args[:-1]) + "/", args[-1]
    return arg + "/", None


def analyse(rules, base_uri):
    score = 0
    rscore = 0
    for rule in rules:
        code, raw, body = get(base_uri + rule['page'])
        if debug:
            print ("= Request %s %s" % (rule['page'], code))
        if rule.get('code'):
            score += 1  # Increment test count
            if rule.get('code') == code:
                rscore += 1
        if rule.get('contains'):
            if isinstance(rule.get('contains'), str):
                score += 1  # Increment test count
                if rule.get('contains') in body:
                    if debug:
                        print ("= Contains")
                    rscore += 1
            elif isinstance(rule.get('contains'), list):
                for contain in rule.get('contains'):
                    score +=1
                    if contain in body:
                        rscore +=1
                        if debug:
                            print ("= Contains")
        if rule.get('hash'):
            score += 1  # Increment test count
            if debug:
                print ("= %s %s" % (rule['page'], hashlib.md5(raw).hexdigest()))
            if rule.get('hash') == hashlib.md5(raw).hexdigest():
                rscore += 1
    fscore = ((rscore / score) * 100)
    if debug:
        print ('Final score: %d' % fscore)
    return(fscore)


def detect(base_uri, root, conf):
    for panel in conf:
        panelcfg=conf[panel]
        if root:
            if root in panelcfg['root']:
                print ("- Candidate to %s" % panel)
                fscore = analyse(panelcfg['rule'], base_uri)
                if fscore > 90:
                    print ("* Found %s at %d%%" % (panel, fscore))
                    return()
    print("- No Root page found, bruteforcing")
    for panel in conf:
        panelcfg=conf[panel]
        fscore = analyse(panelcfg['rule'], base_uri)
        if fscore > 90:
            print ("* Found %s at %d%%" % (panel, fscore))
            return()


# Main Code #####
def main():
    conf = load_conf()
    uri = getparam(1)
    if not uri.startswith("http"):
        uri = "http://%s" % uri
    print("Query on %s" % uri)
    base_uri, root = page2folder(uri)
    print("Base Uri %s, Page: %s" % (base_uri, root))
    result = detect(base_uri, root, conf)


if __name__ == '__main__':
    main()
