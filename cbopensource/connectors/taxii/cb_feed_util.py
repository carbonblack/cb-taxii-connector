import os
import simplejson as json
import traceback
from datetime import datetime, timedelta
from util import TZ_UTC
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

import logging

logger = logging.getLogger(__name__)


class FeedHelper(object):
    def __init__(self, output_dir, feed_name, minutes_to_advance, start_date_str):
        self.output_dir = output_dir
        self.feed_name = feed_name
        self.minutes_to_advance = minutes_to_advance
        self.path = os.path.join(output_dir, feed_name)
        self.details_path = self.path + ".details"
        self.init_feed_details(start_date_str)

        self.start_date = datetime.strptime(
            self.feed_details.get('latest'),
            "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ_UTC)

        self.end_date = self.start_date + timedelta(minutes=self.minutes_to_advance)
        self.done = False
        self.now = datetime.utcnow().replace(tzinfo=TZ_UTC)

        if self.end_date > self.now:
            self.end_date = self.now

    def init_feed_details(self, start_date):
        self.feed_details = {"latest": start_date}
        if os.path.exists(self.details_path):
            try:
                with open(self.details_path, 'rb') as file_handle:
                    self.feed_details = json.loads(file_handle.read())
            except:
                logger.warning(traceback.format_exc())

    def advance(self):
        """
        Returns True if keep going, False if we already hit the end time and cannot advance
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

    def load_existing_feed_data(self):
        reports = []
        if os.path.exists(self.path):
            with open(self.path, 'rb') as file_handle:
                data = json.loads(file_handle.read())
                reports = data.get('reports', [])

        return reports

    def write_feed(self, data):
        try:
            with open(self.path, 'wb') as file_handle:
                file_handle.write(data)
        except Exception as e:
            logger.error(traceback.format_exc())
            return False
        return True

    def save_details(self):
        try:
            self.feed_details['latest'] = self.end_date.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.details_path, 'wb') as file_handle:
                file_handle.write(json.dumps(self.feed_details))
                return True
        except Exception as e:
            logger.error(traceback.format_exc())
            return False


def remove_duplicate_reports(reports):
    out_reports = []
    reportids = set()
    for report in reports:
        if report['id'] in reportids:
            continue
        reportids.add(report['id'])
        out_reports.append(report)
    return out_reports


def build_feed_data(feed_name, display_name, feed_summary, site, icon_link, reports):
    """
    :return:feed as bytes to be written out
    """
    feedinfo = {'name': feed_name,
                'display_name': display_name,
                'provider_url': 'http://' + site,
                'summary': feed_summary,
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': icon_link
                }

    feedinfo = CbFeedInfo(**feedinfo)

    reports = remove_duplicate_reports(reports)

    feed = CbFeed(feedinfo, reports)
    return feed.dump()
