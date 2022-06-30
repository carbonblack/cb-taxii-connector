CHANGELOG.md
# CB EDR Taxii Connector Changelog

## v1.6.7-4
#### Features
 * Added new config option, ioc_exclusions that supports excluding one or more artifact types from Threat Report creations. Reference the cbtaxii.conf.example for more information on this config option.
 
#### Bug Fixes / Changes
 * Fixed a bug that caused only the first configured TAXII connector connection to be run.
 * Now utilizes the time of the fetch for the Threat Report created timestamp as opposed to EPOCH when no timestamp is provided by the indicator itself.
 * Improvements to the cbtaxii.conf.example file for better understanding of config options and defaults.
 * Slight improvements in error reporting/handling
