#!/usr/bin/env python3
# coding=utf-8

import sys
import yaml
from os import listdir
from os.path import isfile, join
import requests
import hashlib
import random
import string
import argparse
import datetime
import logging
from logging.handlers import RotatingFileHandler

version = '0.1.1712'
gen_config = {}
gen_config['verbose'] = False
gen_config['quiet'] = False


def debug():
    if gen_config['verbose']:
        return(rue)
    return(False)


def quiet():
    if gen_config['quiet']:
        return(True)
    return(False)


def logger_init(logger):
    # on met le niveau du logger à DEBUG, comme ça il écrit tout
    if gen_config['verbose']:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Reset urllogger to debug level
    logging.getLogger("requests").setLevel(logging.DEBUG)
    # création d'un formateur qui va ajouter le temps, le niveau
    # de chaque message quand on écrira un message dans le log
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    # création d'un handler qui va rediriger une écriture du log vers
    # un fichier en mode 'append', avec 1 backup et une taille max de 1Mo
    file_handler = RotatingFileHandler('activity.log', 'a', 1000000, 1)
    # on lui met le niveau sur DEBUG, on lui dit qu'il doit utiliser le formateur
    # créé précédement et on ajoute ce handler au logger
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # création d'un second handler qui va rediriger chaque écriture de log
    # sur la console
    if not gen_config['quiet']:
        steam_handler = logging.StreamHandler()
        if gen_config['verbose']:
            steam_handler.setLevel(logging.DEBUG)
        else:
            steam_handler.setLevel(logging.INFO)
            # création d'un formateur qui va ajouter le temps, le niveau
        steam_handler.setLevel(logging.DEBUG)
        steam_handler.setFormatter(formatter)
        logger.addHandler(steam_handler)


# Parse les arguments de la ligne de commande, les retourne avec un dictionnaire..
def parse_arg():
    parser = argparse.ArgumentParser(description='C2ID v%s (c) Thanat0s 2017-%d'% (version, datetime.datetime.now().year))
    subparsers = parser.add_subparsers(help='sub-command help', dest='command')
    parser_s = subparsers.add_parser('seek', help='Identify a CC')
    parser_c = subparsers.add_parser('candidates', help='Print all candidate pages')

    # Update Mode
    parser_c.add_argument('-v', '--verbose', action='store_true', help='verbose mode', dest='verbose')

    # Seek Mode
    parser_s.add_argument('-v', '--verbose', action='store_true', help='verbose mode', dest='verbose')
    parser_s.add_argument('-u', '--uri', required=True, dest='uri', help='Uri to identify')
    parser_s.add_argument('-q', '--quiet', action='store_true', help='quiet', dest='quiet')

    args = parser.parse_args()
    argsdict = vars(args)
    return(argsdict)


def get(uri):
    headers = requests.utils.default_headers()
    headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
    try:
        r = requests.get(uri, timeout=15, headers=headers)
    except requests.exceptions.MissingSchema:
        logger.error('Invalid Scheme')
        return 000, bytes("".encode('utf8')), ""
    except:
        return 000, bytes("".encode('utf8')), ""
        logger.error('Unknown error when fetching')
    return r.status_code, r.content, r.text


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
                logger.info("! Yaml syntax error in %s" % conf_file)
    # logger.debug(conf)
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
        ext = ext.split('?')[0]
        if ext.lower() in ['php', 'html', 'pl', 'htm', 'aspx']:
            return "/".join(args[:-1]) + "/", args[-1].split('?')[0]
    return arg + "/", None


def get404(base_uri):
    ''' Fetch a random page to get a 404
    '''
    pagerandom = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)) + ".html"
    _, raw404, _ = get(base_uri + pagerandom)
    return(raw404)


def analyse(rules, base_uri):
    score = 0
    rscore = 0
    raw404 = True   # Init once
    for rule in rules:
        if rule.get('code') == 404 and raw404:
            raw404 = get404(base_uri)
            if debug:
                logger.debug('Fetched a real 404 page')
            break

    for rule in rules:
        code, raw, body = get(base_uri + rule['page'])
        if debug:
            logger.debug("Requesting %s status code %s" % (rule['page'], code))
        if rule.get('code'):
            score += 1  # ncrement test count
            if rule.get('code') == code:
                if rule.get('code') == 404:
                    if raw != raw404:
                        if debug:
                            logger.debug('Generated 404 page found')
                        rscore += 1
                else:
                    rscore += 1
        if rule.get('contains'):
            if isinstance(rule.get('contains'), str):
                score += 1  # Increment test count
                if rule.get('contains') in body:
                    if debug:
                        logger.debug("Page contains %s" % rule.get('contains'))
                    rscore += 1
            elif isinstance(rule.get('contains'), list):
                for contain in rule.get('contains'):
                    score +=1
                    if contain in body:
                        rscore +=1
                        if debug:
                            logger.debug("Page contains %s" % rule.get('contains'))
        if rule.get('hash'):
            score += 1  # Increment test count
            if debug:
                logger.debug("%s match %s" % (rule['page'], hashlib.md5(raw).hexdigest()))
            if rule.get('hash') == hashlib.md5(raw).hexdigest():
                rscore += 1
    fscore = ((rscore / score) * 100)
    if debug:
        logger.debug('Final score: %d' % fscore)
    return(fscore)


def detect(base_uri, root, conf):
    highscore = {}
    for panel in conf:
        panelcfg=conf[panel]
        if root:
            if root in panelcfg['root']:
                logger.debug("Busting for %s" % panel)
                fscore = analyse(panelcfg['rule'], base_uri)
                if fscore > 90:
                    return(panel, fscore)
                highscore[panel] = fscore
    logger.info("No Root page found, bruteforcing")
    for panel in conf:
        panelcfg=conf[panel]
        fscore = analyse(panelcfg['rule'], base_uri)
        if fscore > 90:
            return(panel, fscore)
        highscore[panel] = fscore

    best = sorted(highscore, key=highscore.__getitem__, reverse=True)[0]
    return(best, highscore[best])


def print_candidates(conf):
    hashtable = {}
    for item in conf:
        for page in (conf[item].get('root')).split(','):
            page = page.strip()
            hashtable[page]=page
    for page in hashtable:
        print(page)


# Main Code #####
def main():
    logger.debug("Start")
    conf = load_conf()
    if gen_config.get('command') == 'seek':

        # Append default scheme if missing.
        if not gen_config.get('uri').startswith("http"):
            gen_config['uri'] = "http://%s" % gen_config.get('uri')
        logger.info("Query on %s" % gen_config.get('uri'))
        base_uri, root = page2folder(gen_config.get('uri'))
        logger.debug("Base Uri %s, Page: %s" % (base_uri, root))
        result, score = detect(base_uri, root, conf)
        if quiet():
            print("Found %s at %d%%" % (result, score))
        else:
            logger.info("Found %s at %d%%" % (result, score))

    elif gen_config.get('command') == 'candidates':
        print_candidates(conf)


logger = logging.getLogger()
gen_config.update(parse_arg())  # Merge config with parameters
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger_init(logger)

if __name__ == '__main__':
    main()
