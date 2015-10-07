
import logging
from collections import Iterable
import re
import asyncio
import functools

import aiohttp


STRING_TYPES = (str, bytes, bytearray)

logger = logging.getLogger('vk')


try:
    # Python 2
    from urllib import urlencode
    from urlparse import urlparse, parse_qsl
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qsl, urlencode


try:
    import simplejson as json
except ImportError:
    import json


try:
    # Python 2
    raw_input = raw_input
except NameError:
    # Python 3
    raw_input = input


def json_iter_parse(response_text):
    decoder = json.JSONDecoder(strict=False)
    idx = 0
    while idx < len(response_text):
        obj, idx = decoder.raw_decode(response_text, idx)
        yield obj


def stringify_values(dictionary):
    stringified_values_dict = {}
    for key, value in dictionary.items():
        if isinstance(value, Iterable) and not isinstance(value, STRING_TYPES):
            value = ','.join(map(str, value))
        stringified_values_dict[key] = value
    return stringified_values_dict


def get_url_query(url):
    parsed_url = urlparse(url)
    url_query = parse_qsl(parsed_url.fragment)
    # login_response_url_query can have multiple key
    url_query = dict(url_query)
    return url_query


def get_form_action(html):
    form_action = re.findall(r'<form(?= ).* action="(.+)"', html)
    if form_action:
        return form_action[0]


def data_required(f):

    @functools.wraps(f)
    @asyncio.coroutine
    def wrapper(cls, *args, **kwargs):

        if cls._data is None:

            cls._data = yield from cls.response.read()

        return (yield from f(cls, *args, **kwargs))

    return wrapper


class RequestsLikeResponse:

    def __init__(self, aiohttp_response):

        self.response = aiohttp_response
        self.headers = self.response.headers
        self._data = None

    @data_required
    @asyncio.coroutine
    def text(self):

        try:

            return bytes.decode(self._data, encoding="utf-8")

        except UnicodeDecodeError:

            return bytes.decode(self._data, encoding="cp1251")

    @data_required
    @asyncio.coroutine
    def json(self):

        return json.loads((yield from self.text()))

    @property
    def url(self):

        return self.response.url

    def raise_for_status(self):

        if 400 <= self.status_code <= 599:

            raise Exception(str.format("Bad status code '{}'", self.response.status_code))

    @property
    def status_code(self):

        return self.response.status

    def __getattr__(self, name):

        raise AttributeError(str.format("No '{}' attribute", name))


class LoggingSession(aiohttp.ClientSession):
    def _request(self, method, url, **kwargs):
        logger.debug('Request: %s %s, params=%r, data=%r', method, url, kwargs.get('params'), kwargs.get('data'))
        response = RequestsLikeResponse((yield from super(LoggingSession, self)._request(method, url, **kwargs)))
        logger.debug('Response: %s %s', response.status_code, response.url)
        return response
