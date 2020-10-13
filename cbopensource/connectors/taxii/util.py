#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
import string
import sys
import time
import unicodedata
from datetime import timedelta, tzinfo
from logging.handlers import RotatingFileHandler
from typing import Union

ZERO = timedelta(0)


class UTC(tzinfo):
    """
    Conversion class for UTC handling.
    """

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


TZ_UTC = UTC()


def cleanup_string(filename: str) -> str:
    """
    Cleanup the provided possible unicode string and reduce it to clean-text usable for a filename.

    :param filename: submitted filename
    :return: cleansed name
    """
    valid_chars = "%s%s" % (string.ascii_letters, string.digits)
    newname = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode("utf-8")
    s = ''.join([c for c in newname if c in valid_chars])
    return s.lower()


# NOTE: currently unused; retain for later needs
# noinspection PyUnusedFunction
def create_stdout_log(name: str, level: Union[int, str]) -> logging.Logger:
    """
    Creates logging stream to stdout.

    :param name: name of the logger
    :param level: logging level (one of [ERROR, WARNING, INFO, DEBUG] or integer equivalent
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


# NOTE: currently unused; retain for later needs
# noinspection PyUnusedFunction
def create_rotating_log(name: str, path: str, level: Union[int, str], num_bytes: int,
                        backup_count: int) -> logging.Logger:
    """
    Creates a logging stream to a rotating set of files.

    :param name: log name
    :param path: path to the base log file
    :param level: logging level (one of [ERROR, WARNING, INFO, DEBUG] or integer equivalent
    :param num_bytes: maximum bytes before roll-over
    :param backup_count: number of rolled-over logfiles to retain
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=num_bytes, backupCount=backup_count)  # 1 MB
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
