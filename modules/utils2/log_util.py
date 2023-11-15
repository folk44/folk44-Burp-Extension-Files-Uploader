import logging
from .datetime_util import DatetimeUtil


class LogUtil(object):

    def __init__(self):
        pass

    @staticmethod
    def debug(message):

        logging.debug(message)

    def info(self, message):

        logging.info(message)

    def info_with_datetime(self, message):

        logging.info('[' + DatetimeUtil().now_iso_string() + '] ' + message)

    def exception(self, e):

        logging.exception(e)
