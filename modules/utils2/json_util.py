import collections
import json
from .log_util import LogUtil


class JSONUtil(object):

    def __init__(self, json_string):

        self.json_string = json_string

    def to_odict(self):

        try:
            return json.loads(self.json_string, object_pairs_hook=collections.OrderedDict)
        except ValueError as e:
            LogUtil().exception(e)
            return collections.OrderedDict()
