# Modifications Notice

This repository is a fork of [ONLYOFFICE/Docker-DocumentServer](https://github.com/ONLYOFFICE/Docker-DocumentServer).

## Modified By
USDA (United States Department of Agriculture)  
Maintained by: qflowsystems

## Summary of Changes

### FIPS 140-2/140-3 Compliance
- Added OpenSSL FIPS provider build and installation to the main `Dockerfile`
- Created FIPS-enabled OpenSSL configuration (`/etc/ssl/openssl-fips.cnf`)
- Added `Dockerfile.fips` - RHEL UBI 9 based image with native FIPS support
- Added `Dockerfile.fips-layer` - Layer to add FIPS support to existing DocumentServer images
- Modified `run-document-server.sh` to auto-detect FIPS mode on the host system

### Security Enhancements
- Container configured to run as non-root user where applicable
- File system permissions configured according to least privilege principles

## Date of Modifications
February 2026

## License
This work remains licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).  
See [LICENSE.txt](./LICENSE.txt) for the full license text.

## Source Code Availability
In compliance with AGPL-3.0 Section 13, the complete source code for this modified version is available at:  
https://github.com/qflowsystems/OnlyOffice-Docker-DocumentServer

## Original Project
- Repository: https://github.com/ONLYOFFICE/Docker-DocumentServer
- Maintainer: Ascensio System SIA
- License: AGPL-3.0
