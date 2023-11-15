from dateutil import parser


class StringBaseUtil(object):

    def __init__(self, string):
        self.string = string

    def to_datetime(self):
        return parser.parse(self.string).replace(tzinfo=None)

