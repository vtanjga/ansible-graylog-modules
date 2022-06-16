# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Released
### Added
- added get_input_id function used when id is not provided for delete action and for creation of extractors
- added create_extractors

### Changed
- module should work with python 2 and 3, so urlparse is used if version is lower than 3, urllib.parse
- delete action on inputs uses name of the input


### Removed

## [1.0.0] 2022-01-27
