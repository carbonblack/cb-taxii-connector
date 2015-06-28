
import sys
import string
import logging
import time
import unicodedata
from datetime import timedelta, tzinfo
from logging.handlers import RotatingFileHandler


def cleanup_string(filename):
#    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    valid_chars = "%s%s" % (string.ascii_letters, string.digits)
    newname = unicodedata.normalize('NFKD', unicode(filename)).encode('ASCII', 'ignore')
    s = ''.join(c for c in newname if c in valid_chars)
    return s.lower()

ZERO = timedelta(0)
HOUR = timedelta(hours=1)

class UTC(tzinfo):
    """UTC"""
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

TZ_UTC = UTC()


def create_stdout_log(name, level):
    """
    Creates a rotating log
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # add a rotating handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger



def create_rotating_log(name, path, level, num_bytes, backup_count):
    """
    Creates a rotating log
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=num_bytes, backupCount=backup_count) #1 MB
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

