# Changelog

## [0.10.2](https://github.com/unified-systems-com/computing-core-tap/compare/v0.10.1...v0.10.2) (2026-10-21)


### Features

* **computing_core:** RUNS_PACKAGE, USES_KEY and an operating system running a program ([0df4b62](https://github.com/unified-systems-com/computing-core-tap/commit/0df4b62f3da6b6cdb2fc41cd972fc772f250556d))
* **computing_core:** RUNS_PACKAGE, USES_KEY and an operating system running a program ([e59881e](https://github.com/unified-systems-com/computing-core-tap/commit/e59881e0dd5c540d99495e84287c2949d8a9b64d))


### Bug Fixes

* **release:** set the release-please manifest to the released version, 0.10.1 ([45aad44](https://github.com/unified-systems-com/computing-core-tap/commit/45aad4428feb9f806888832a767a5fce2f9f0acf))
* **release:** set the release-please manifest to the released version, 0.10.1 ([90e2d1e](https://github.com/unified-systems-com/computing-core-tap/commit/90e2d1e53df8f27f9337d4f35e2677e5a9317895))

## [0.5.0](https://github.com/unified-systems-com/computing-core-tap/compare/v0.4.0...v0.5.0) (2026-10-08)


### ⚠ BREAKING CHANGES

* computing_core__user no longer exists. samsite seeds it and pins <0.5. It moves to identity_core__human in unified-systems-com/samsite-tap#33.
* FETCHES_DOCUMENT__computing_core and HOSTS_DOCUMENT__computing_core no longer exist. samsite seeds HOSTS_DOCUMENT, emits FETCHES_DOCUMENT and draws HOSTS_DOCUMENT in its landing projection; it pins <0.5 and must move before taking 0.5.

### Features

* host, os_user and os_group; retire computing_core__user ([958aaee](https://github.com/unified-systems-com/computing-core-tap/commit/958aaee7ec26cb1ff3b207d607b78058b0cdf49e))
* retire FETCHES_DOCUMENT and HOSTS_DOCUMENT [via highbar] ([71be3ec](https://github.com/unified-systems-com/computing-core-tap/commit/71be3ec2b7653b52299dfad8d45a5f1abd741739))


### Bug Fixes

* **boot:** pin the commit beside every git source's rev in the CI record ([f0ce777](https://github.com/unified-systems-com/computing-core-tap/commit/f0ce777f8171b185c469b48508ebb28beee2716b))
* **boot:** pin the commit beside every git source's rev in the CI record [via bom-bom] ([7ded2ba](https://github.com/unified-systems-com/computing-core-tap/commit/7ded2bace4a59f64deeffd570ae79259c67b4430))
* **manifest:** raise the tap floor to 0.3.0 ([9c61074](https://github.com/unified-systems-com/computing-core-tap/commit/9c61074a08912bfa7d8cb657424a5c8ac8fc39d8))


### Documentation

* cite issues, not session rulings, in code and spec ([2b52adc](https://github.com/unified-systems-com/computing-core-tap/commit/2b52adce02fa296a64198f0440dcbd4d8846a24e))
* **models:** say plainly that a POSIX rename is a new os_user / os_group ([8ec1aa4](https://github.com/unified-systems-com/computing-core-tap/commit/8ec1aa48738dc9c13c893ee999c4ae1cc0e6cc0b))
