#  coding: utf-8
#  VMware Carbon Black EDR Taxii Connector © 2013-2020 VMware, Inc. All Rights Reserved.
################################################################################

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import simplejson as json
from cbfeeds import CbFeed, CbFeedInfo

from .util import TZ_UTC

_logger = logging.getLogger(__name__)


class FeedHelper(object):
    """
    Class to assist in creating feeds.
    """

    def __init__(self, output_dir: str, feed_name: str, minutes_to_advance: int, start_date_str: str,
                 reset_start_date: bool = False):
        """
        Initialize the class.

        :param output_dir: directory where feed information is written
        :param feed_name: the name of the new edr feed
        :param minutes_to_advance: minutes to go forward from the start date
        :param start_date_str: starting date and time
        :param reset_start_date: if True, update the stashed start date
        """
        self.output_dir = output_dir
        self.feed_name = feed_name
        self.minutes_to_advance = minutes_to_advance
        self.path = os.path.join(output_dir, feed_name)
        self.details_path = self.path + ".details"
        self.feed_details: Optional[Dict[str, str]] = None

        self.init_feed_details(start_date_str, ignore_feed_details=reset_start_date)

        self.start_date = datetime.strptime(
            self.feed_details.get('latest'),
            "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ_UTC)

        self.end_date = self.start_date + timedelta(minutes=self.minutes_to_advance)
        self.done = False
        self.now = datetime.utcnow().replace(tzinfo=TZ_UTC)

        if self.end_date > self.now:
            self.end_date = self.now

    def init_feed_details(self, start_date: str, ignore_feed_details=False) -> None:
        """
        Initialize the feed details internal structure with information on disk.

        :param start_date: starting date and time as a string
        :param ignore_feed_details: If True, don't load details
        """
        self.feed_details = {"latest": start_date}
        if os.path.exists(self.details_path) and not ignore_feed_details:
            try:
                with open(self.details_path, 'r') as file_handle:
                    self.feed_details = json.loads(file_handle.read())
            except Exception as e:
                _logger.warning(f"{e}")

    def advance(self) -> bool:
        """
        Returns True if we need to advance to the next time interval.  If the time interval exceeds
        the current time, we will advance but set our flag to stop after that.

        :return: True or False
        """
        if self.done:
            return False

        self.start_date = self.end_date
        self.end_date += timedelta(minutes=self.minutes_to_advance)
        if self.end_date > self.now:
            self.end_date = self.now
            self.done = True

        return True

    def load_existing_feed_data(self) -> List[Dict[str, Any]]:
        """
        Read in existing data into memory.

        :return: list of reports
        """
        reports = []
        if os.path.exists(self.path):
            with open(self.path, 'r') as file_handle:
                inp = file_handle.read()
                data = json.loads(inp)
                reports = data.get('reports', [])

        return reports

    def write_feed(self, data: str) -> bool:
        """
        Write feed information to a file.

        :param data: feed info in JSON string forma
        :return: True if successful
        """
        try:
            with open(self.path, 'w') as file_handle:
                file_handle.write(data)
        except Exception as e:
            _logger.error(f"{e}")
            return False
        return True

    def save_details(self) -> bool:
        """
        Save details to disk.
        :return: True if successful
        """
        try:
            self.feed_details['latest'] = self.end_date.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.details_path, 'w') as file_handle:
                file_handle.write(json.dumps(self.feed_details))
                return True
        except Exception as e:
            _logger.error(f"{e}")
            return False

    def dump_feedinfo(self) -> Dict[str, Any]:
        """
        Read in existing feed for display.

        :return: list of reports
        """
        if os.path.exists(self.path):
            with open(self.path, 'r') as file_handle:
                inp = file_handle.read()
                data = json.loads(inp)
                info = data.get('feedinfo', {})

        return info


def remove_duplicate_reports(reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove reports with the same id.

    :param reports: list of incoming reports
    :return: filtered reports
    """
    out_reports = []
    reportids = set()
    for report in reports:
        if report['id'] in reportids:
            continue
        reportids.add(report['id'])
        out_reports.append(report)
    return out_reports


def build_feed_data(feed_name: str, display_name: str, feed_summary: str, site: str, icon_link: str,
                    reports: List[Dict[str, Any]]) -> str:
    """
    Return a feed definition as a JSON string definition.

    :param feed_name: the short name of the feed
    :param display_name: the display name of the feed
    :param feed_summary: the feed summary
    :param site: the site name
    :param icon_link: path to the icon source
    :param reports:  List of gathered reports
    :return: feed as JSON string
    """

    feedinfo = {'name': feed_name,
                'display_name': display_name,
                'provider_url': 'http://' + site,
                'summary': feed_summary,
                'tech_data': "There are no requirements to share any data to receive this feed.",
                }

    # handle optionals
    if icon_link:
        feedinfo['icon'] = icon_link

    feedinfo = CbFeedInfo(**feedinfo)

    reports = remove_duplicate_reports(reports)

    feed = CbFeed(feedinfo, reports)
    return feed.dump()
