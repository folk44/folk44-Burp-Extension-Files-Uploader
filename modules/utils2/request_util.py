import requests
from google.appengine.api import urlfetch
from requests.exceptions import ConnectionError
from .env_util import EnvUtil
from .json_util import JSONUtil


class RequestUtil(object):

    def __init__(self, url):
        self.url = url
        self.appengine_env = EnvUtil().appengine_environment()
        self._response = None
        self._content = None

    def get(self):

        if self._response:
            return self._response

        else:

            if self.appengine_env:

                _response = urlfetch.fetch(
                    self.url,
                    deadline=15
                )

                self._response = _response
                self._content = _response.content

                return _response

            else:

                _response = requests.get(self.url)
                return _response

    response = get

    def content(self):

        self.get()
        return self._content

    def content_dict(self):

        return JSONUtil(self.content()).to_odict()

    def is_ok(self):

        try:
            return self.response().status_code == 200

        except ConnectionError:
            return False

    def to_https(self):

        if 'https://' in self.url:
            return self.url

        else:
            return self.url.replace('http', 'https')
