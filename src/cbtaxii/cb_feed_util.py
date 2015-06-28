
import os
import simplejson as json
import pprint
import traceback
import time
import dateutil.parser as date_parser
import stix.bindings.stix_core as stix_core_binding
import cybox

from cbfeeds import CbReport

from datetime import datetime, timedelta
from util import TZ_UTC
from cbfeeds import CbFeed
from cbfeeds import CbFeedInfo

class FeedHelper(object):
    def __init__(self, output_dir, feed_name, minutes_to_advance, start_date_str, export_mode):
        self.output_dir = output_dir
        self.feed_name = feed_name
        self.export_mode = export_mode
        self.minutes_to_advance = minutes_to_advance
        self.path = os.path.join(output_dir, feed_name)
        self.details_path = self.path + ".details"
        self.feed_details = {"latest": start_date_str}
        if not self.export_mode and os.path.exists(self.details_path):
            try:
                feed_details_file = file(self.details_path, "rb")
                self.feed_details = json.loads(feed_details_file.read())
            except:
                traceback.print_exc()
        self.start_date = datetime.strptime(self.feed_details.get('latest'), "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ_UTC)
        self.end_date = self.start_date + timedelta(minutes=self.minutes_to_advance)
        self.done = False
        self.now = datetime.utcnow().replace(tzinfo=TZ_UTC)
        if self.end_date > self.now:
            self.end_date = self.now

    def advance(self):
        """
        returns true if keep going, false if we already hit the end time and cannot advance
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
            data = file(self.path, 'rb').read()
            data = json.loads(data)
            reports = data.get('reports', [])
        return reports

    def write_feed(self, data):
        f = file(self.path, 'wb')
        f.write(data)
        f.close()
        return True # TODO -- when to return False?

    def save_details(self):
        self.feed_details['latest'] = self.end_date.strftime("%Y-%m-%d %H:%M:%S")

        feed_details_file = file(self.details_path, "wb")
        feed_details_file.write(json.dumps(self.feed_details))
        feed_details_file.close()


def build_feed_data(feed_name, feed_description, site, icon_link, reports):
    """
    :return:feed as bytes to be written out
    """
    feedinfo = {'name': feed_name,
                'display_name': feed_description,
                'provider_url': 'http://' + site,
                'summary': "TAXII Feed %s" % feed_description,
                'tech_data': "There are no requirements to share any data to receive this feed.",
                'icon': icon_link
                }

    feedinfo = CbFeedInfo(**feedinfo)

    feed = CbFeed(feedinfo, reports)
    return feed.dump()


def lookup_admin_api_token():
    from cb.utils import Config
    from cb.utils.db import db_session_context
    from cb.db.core_models import User

    cfg = Config()
    cfg.load('/etc/cb/cb.conf')
    db_session_context = db_session_context(cfg)
    db_session = db_session_context.get()

    user = db_session.query(User).filter(User.global_admin == True).first()

    api_token = user.auth_token

    db_session_context.finish()

    return api_token


