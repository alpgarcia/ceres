#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Authors:
#     Alberto Pérez García-Plaza <alpgarcia@bitergia.com>
#


import certifi
import configparser
import datetime
import logging
import re
import requests
import sys
import time

from collections import namedtuple
from dateutil import parser as date_parser
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import NotFoundError
from elasticsearch_dsl import Search

GIT_MAPPING_FILE = "git_mapping.json"
# Logging formats
LOG_FORMAT = "[%(asctime)s - %(levelname)s] - %(message)s"
DEBUG_LOG_FORMAT = "[%(asctime)s - %(name)s - %(levelname)s] - %(message)s"

logger = logging.getLogger(__name__)


def parse_es_section(parser, es_section):
    ES_config = namedtuple('ES_config',
                           ['es_read', 'es_write', 'es_read_git_index',
                            'es_write_git_index'])

    user = parser.get(es_section, 'user')
    password = parser.get(es_section, 'password')
    host = parser.get(es_section, 'host')
    port = parser.get(es_section, 'port')
    path = parser.get(es_section, 'path')
    es_read_git_index = parser.get(es_section, 'index_git_raw')

    host_output = parser.get(es_section, 'host_output')
    port_output = parser.get(es_section, 'port_output')
    user_output = parser.get(es_section, 'user_output')
    password_output = parser.get(es_section, 'password_output')
    path_output = parser.get(es_section, 'path_output')
    es_write_git_index = parser.get(es_section, 'index_git_output')

    connection_input = "https://" + user + ":" + password + "@" + host + ":" \
                       + port + "/" + path
    print("Input ES:", connection_input)
    es_read = Elasticsearch([connection_input], use_ssl=True, verity_certs=True,
                            ca_cert=certifi.where(), timeout=100)

    credentials = ""
    if user_output:
        credentials = user_output + ":" + password_output + "@"

    connection_output = "http://" + credentials + host_output + ":" \
                        + port_output + "/" + path_output
    # es_write = Elasticsearch([connection_output], use_ssl=True,
    #                           verity_certs=True, ca_cert=certifi.where(),
    #                           scroll='300m', timeout=100)
    print("Output ES:", connection_output)
    es_write = Elasticsearch([connection_output])

    return ES_config(es_read=es_read, es_write=es_write,
                     es_read_git_index=es_read_git_index,
                     es_write_git_index=es_write_git_index)


def parse_config(general_section='General', github_section='GitHub',
                 es_section='ElasticSearch'):
    Config = namedtuple('Config', ['es_config', 'api_token', 'log_level',
                                   'size', 'inc'])

    parser = configparser.ConfigParser()
    conf_file = '.settings'
    fd = open(conf_file, 'r')
    parser.read_file(fd)
    fd.close()

    es_config = parse_es_section(parser, es_section=es_section)

    api_token = parser.get(github_section, 'api_token')

    log_level = parser.get(general_section, 'log_level')
    size = parser.get(general_section, 'size')
    inc = parser.get(general_section, 'inc')

    return Config(es_config=es_config,
                  api_token=api_token,
                  log_level=log_level,
                  size=size,
                  inc=inc)


def get_repo_collabs(github_repo, api_token):
    """Query GitHub for repo collaborators

    :param str github_repo: string following pattern: <owner>/<repo>
    :param str api_token: GitHub API token
    :return: dict containing users as keys and a commiter field with boolean type:

        {
            "user": {
                "commiter": True|False
            }
        }
    :rtype: dict
    :raises ValueError: repo not found in GitHub API
    """
    next_link = 'https://api.github.com/repos/' + github_repo + '/collaborators'
    headers = {'Authorization': 'token %s' % api_token}

    repo_users = {}

    while next_link:
        logger.debug('Next:' + next_link)
        r = requests.get(next_link, headers=headers)

        if rate_limit_exceeded(r):
            # If limit exceeded, wait until reset and query again
            r = requests.get(next_link, headers=headers)

        logger.debug('Reponse %s', r.status_code)

        if r.status_code != 200:
            raise ValueError('Repo not found: ' + next_link + ": " + r.headers + '\n' + r.content)

        # Once it is used, empty next link
        next_link = None

        if 'Link' in r.headers:
            m = re.search('<(\S+)>; rel="next"', r.headers['Link'])
            if m is not None and len(m.groups()) == 1:
                next_link = m.group(1)

        for user_json in r.json():
            user_info = {}
            username = user_json['login']
            # user_info['username'] = username
            user_info['commiter'] = user_json['permissions']['push']
            # user_info['repo_name'] = repo_name
            # user_info['github_repo'] = github_repo
            repo_users[username] = user_info

    return repo_users


def get_author_login(github_repo, commit_sha, api_token):
    """Query GitHub API for commit author login

    :param str github_repo: string following pattern: <owner>/<repo>
    :param str commit_sha: SHA-1 of the desired commit
    :param str api_token: GitHub API token
    :return: commit author login
    :rtype: str
    :raises ValueError: commit not found in GitHub API or it doesn't contain info about author login,
                        probably because author doesn't have a GitHub account anymore
    """

    api_url = 'https://api.github.com/repos/' + github_repo + '/commits/' + commit_sha
    headers = {'Authorization': 'token %s' % api_token}

    logger.debug('Query for commit:' + api_url)
    r = requests.get(api_url, headers=headers)

    if rate_limit_exceeded(r):
        # If limit exceeded, wait until reset and query again
        r = requests.get(api_url, headers=headers)

    logger.debug('Reponse %s', r.status_code)

    if r.status_code != 200:
        raise ValueError('Commit not found: ' + api_url)

    if r.json()['author'] is None:
        raise ValueError('Commit with no author: ' + api_url)

    return r.json()['author']['login']


def rate_limit_exceeded(r):
    """Checks rate limit and sleeps until reset if needed
    :param r: API response
    :return: True if limit exceeded, ioc False
    """
    logger.debug('Rate Limit:  ' + r.headers['X-RateLimit-Limit'])
    logger.debug('Rate Limit Remaining:  ' + r.headers['X-RateLimit-Remaining'])
    logger.debug('Rate Limit Reset:  ' + r.headers['X-RateLimit-Reset'])
    # Rate limit exceeded
    if r.status_code == 403:
        waiting_time = int(r.headers['X-RateLimit-Reset']) - datetime.datetime.now().timestamp() + 1
        if waiting_time < 0:
            waiting_time = 0
        logger.info('Rate limit reached: %s seconds to reset...zZz', waiting_time)
        time.sleep(waiting_time)

        return True

    else:
        return False


def configure_logging(info=False, debug=False):
    """Configure logging
    The function configures log messages. By default, log messages
    are sent to stderr. Set the parameter `debug` to activate the
    debug mode.
    :param info: set the info mode
    :param debug: set the debug mode
    """
    if info:
        logging.basicConfig(level=logging.INFO,
                            format=LOG_FORMAT)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('urrlib3').setLevel(logging.WARNING)
        logging.getLogger('elasticsearch').setLevel(logging.WARNING)
    elif debug:
        logging.basicConfig(level=logging.DEBUG,
                            format=DEBUG_LOG_FORMAT)
    else:
        logging.basicConfig(level=logging.WARNING,
                            format=LOG_FORMAT)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('urrlib3').setLevel(logging.WARNING)
        logging.getLogger('elasticsearch').setLevel(logging.WARNING)


def init_write_index(es_write, es_write_index):
    """Initializes ES write index
    """
    logger.info("Initializing index: " + es_write_index)
    es_write.indices.delete(es_write_index, ignore=[400, 404])

    # Read Git Mapping
    with open(GIT_MAPPING_FILE) as f:
        git_mapping = f.read()

    es_write.indices.create(es_write_index, body=git_mapping)


def upload_data(commits, es_write_index, es_write):
    # Uploading info to the new ES
    docs = []
    for hit in commits:
        header = {
            "_index": es_write_index,
            "_type": "item",
            "_id": hit["_id"],
            "_source": hit["_source"]
        }
        docs.append(header)
    helpers.bulk(es_write, docs)
    logger.info("Written: " + str(len(docs)))


def get_search_query(es_write, es_write_index, incremental):
    query = {"match_all": {}}
    sort = [{"metadata__timestamp": {"order": "asc"}}]
    if incremental.lower() == 'true':
        search = Search(using=es_write, index=es_write_index)
        # from:to parameters (=> from: 0, size: 0)
        search = search[0:0]
        search = search.aggs.metric('max_date', 'max', field='metadata__timestamp')

        try:
            response = search.execute()

            if response.to_dict()['aggregations']['max_date']['value'] is None:
                msg = "No data for 'metadata__timestamp' field found in "
                msg += es_write_index + " index"
                logger.warning(msg)
                init_write_index(es_write, es_write_index)

            else:
                # Incremental case: retrieve items from last item in ES write index
                max_date = response.to_dict()['aggregations']['max_date']['value_as_string']
                max_date = date_parser.parse(max_date).isoformat()

                logger.info("Starting retrieval from: " + max_date)
                query = {"range": {"metadata__timestamp": {"gte": max_date}}}

        except NotFoundError:
            logger.warning("Index not found: " + es_write_index)
            init_write_index(es_write, es_write_index)

    else:
        init_write_index(es_write, es_write_index)
    search_query = {
        "query": query,
        "sort": sort
    }
    return search_query


def init_extra_args():
    """

    :return: extra args to be passed to process_item method
    """

    extra_args = {}
    # Cache of repositories storing, for each username, whether she is a
    # commiter in that repo.
    extra_args['repo_cache'] = {}

    return extra_args


def process_hit(api_token, hit, **kwargs):
    """

    :param api_token:
    :param hit:
    :param kwargs: extra args needed for item processing
    :return: number of items processed and list of items to upload. Some items can be ready to upload
             with no process needed, so they will be in the list but not counted as processed,
             that's way the method return both.
    """

    repo_cache = kwargs['repo_cache']

    items = []
    processed = 0

    # Following field appears in GitHub repos only
    github_repo = hit["_source"]["github_repo"]
    commit_sha = hit["_source"]["hash"]
    logger.debug("Repo: " + github_repo)
    logger.debug("Hash: " + commit_sha)
    try:

        github_username = get_author_login(github_repo, commit_sha, api_token)
        logger.debug("Login: " + github_username)

        if github_repo in repo_cache:
            # Get info from  Cache
            logger.debug("Getting info from cache for " + github_repo)
            repo_users = repo_cache[github_repo]
        else:
            logger.info("Adding repo to cache: " + github_repo)
            repo_users = get_repo_collabs(github_repo, api_token)
            # Add repo to cache
            repo_cache[github_repo] = repo_users
            logger.info("Cache size: " + str(len(repo_cache)))

        # Look for username in repo data
        commiter = False
        if github_username in repo_users:
            if repo_users[github_username]["commiter"]:
                commiter = True
        else:
            logger.debug("User " + github_username + " not found in repo: " + github_repo)

        hit["_source"]["github_login"] = github_username

        if commiter:
            logger.debug("commiter: " + github_username)
            hit["_source"]["is_commiter"] = 1
            hit["_source"]["is_contributor"] = 0
            hit["_source"]["contributor_type"] = "commiter"
        else:
            logger.debug("contributor: " + github_username)
            hit["_source"]["is_commiter"] = 0
            hit["_source"]["is_contributor"] = 1
            hit["_source"]["contributor_type"] = "contributor"

        processed += 1

    except ValueError as err:
        logger.debug("{0}".format(err))
        # Add default values for being able to retrieve those
        # unprocessed commits in the new index
        hit["_source"]["github_login"] = "unknown"
        hit["_source"]["is_commiter"] = 0
        hit["_source"]["is_contributor"] = 0
        hit["_source"]["contributor_type"] = "unknown"
    # Add all commits to the ne index, processed or not
    items.append(hit)

    return processed, items


def analyze_git(es_read, es_write, es_read_index, es_write_index, api_token,
                size, incremental):
    search_query = get_search_query(es_write, es_write_index, incremental)

    logger.info(search_query)

    logger.info("Start reading items...")

    extra_args = init_extra_args()

    commits = []
    cont = 0
    total_processed = 0

    for hit in helpers.scan(es_read, search_query, scroll='300m', index=es_read_index,
                            preserve_order=True):

        cont = cont + 1

        logger.debug("Items: " + str(cont))

        logger.debug("[Hit] metadata__timestamp: " + hit["_source"]['metadata__timestamp'])

        processed, items = process_hit(api_token=api_token, hit=hit, **extra_args)

        total_processed += processed
        commits.extend(items)

        if cont % size == 0:
            logger.info("Total Items read/procesed/to be written: " + str(cont) + '/' +
                        str(total_processed) + '/' + str(len(commits)))

            upload_data(commits, es_write_index, es_write)

            # Reset list of commits
            commits = []

    # In case we have some commits pending, process them
    if len(commits) > 0:
        logger.info("Total Items read/procesed: " + str(cont) + '/' + str(total_processed))
        upload_data(commits, es_write_index, es_write)


def main():
    # Read settings
    config = parse_config()

    if config.log_level == 'info':
        configure_logging(info=True)
    elif config.log_level == 'debug':
        configure_logging(debug=True)
    else:
        configure_logging()

    # Read Enriched Index
    analyze_git(config.es_config.es_read,
                config.es_config.es_write,
                config.es_config.es_read_git_index,
                config.es_config.es_write_git_index,
                config.api_token,
                int(config.size),
                incremental=config.inc)

    print('This is the end.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        s = "\n\nReceived Ctrl-C or other break signal. Exiting.\n"
        sys.stdout.write(s)
        sys.exit(0)
    except RuntimeError as e:
        s = "Error: %s\n" % str(e)
        sys.stderr.write(s)
        sys.exit(1)
