import json

from collections import OrderedDict

odict = OrderedDict


class DictUtil(object):

    def __init__(self, _dict):
        self._dict = _dict

    def sorted(self):
        return OrderedDict(sorted(self._dict.items()))

    @classmethod
    def merge(cls, *dict_args):
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result

    def key_value_tuples(self):

        return [(key, value) for key, value in self._dict.iteritems()]

    def key_value_output(self):

        output = ''
        for _tuple in self.key_value_tuples():
            output += str(_tuple)
            output += '\n'

        return output

    def to_json_string(self):

        return json.dumps(self._dict)
