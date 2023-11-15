from datetime import datetime
from .input_util import InputUtil


class DatetimeUtil(object):

    def __init__(self, datetime_param=None):

        self._datetime = InputUtil(datetime_param).to_datetime()

    def pretty_string(self):
        return self._datetime.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def now():
        return datetime.utcnow().replace(microsecond=0)

    @staticmethod
    def now_string():
        return datetime.utcnow().replace(microsecond=0).isoformat()

    now_iso_string = now_string

    def to_iso_format(self):
        return self._datetime.isoformat()

    to_iso_format_string = to_iso_format
