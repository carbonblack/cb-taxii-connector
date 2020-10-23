CHANGELOG.md
# CB EDR Taxii Connector Changelog

## v2.0.0
#### Features
 * Converted to python3
 * Hardened configuration to include sanity checks in order to catch configuration problems BEFORE scanning

## v1.6.7
#### Features
 * Provides option to pull all reports
#### Bug Fixes / Changes
 * CB-26632 - Adds "reset_start_date=True/False" an option to force the connector to re-pull all reports from the configured STIX/TAXII sources.

