import six
from datetime import datetime

from .string_base_util import StringBaseUtil


class InputUtil(object):

    def __init__(self, _input):
        self.input = _input

    def to_datetime(self):

        if self.is_string():
            return StringBaseUtil(self.input).to_datetime()

        if self.is_datetime():
            return self.input

    def is_string(self):

        return isinstance(self.input, six.string_types)

    def is_datetime(self):

        return isinstance(self.input, datetime)
