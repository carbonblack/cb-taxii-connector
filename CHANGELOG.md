CHANGELOG.md
# CB EDR Taxii Connector Changelog

## v1.6.7-4
#### Features
 * Added new config option, ioc_exclusions that supports excluding one or more artifact types from Threat Report creations. Reference the cbtaxii.conf.example for more information on this config option.
 
#### Bug Fixes / Changes
 * Fixed a bug that caused only the first configured TAXII connector connection to be run.
 * Fixed a bug where building via PyInstaller led to a broken cb-taxii-connector binary due to missing packages in the spec file.
 * Now the oldest Threat Reports are truncated, versus the newest, when a Threat Feed reaches its maximum Threat Report size.
 * Now utilizes the time of the fetch for the Threat Report created timestamp as opposed to EPOCH when no timestamp is provided by the indicator itself.
 * Improvements to the cbtaxii.conf.example file for better understanding of config options and defaults.
 * Improvements to the documentation, including documentation of build steps.
 * Slight improvements in error reporting/handling
