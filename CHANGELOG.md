# Changelog

[PyPI History][1]

[1]: https://pypi.org/project/google-cloud-webrisk/#history
### [1.4.1](https://www.github.com/googleapis/python-webrisk/compare/v1.4.0...v1.4.1) (2021-07-20)


### Bug Fixes

* **deps:** pin 'google-{api,cloud}-core', 'google-auth' to allow 2.x versions ([#104](https://www.github.com/googleapis/python-webrisk/issues/104)) ([49314f2](https://www.github.com/googleapis/python-webrisk/commit/49314f2a102b5074874fd4d8b2c4d0e30c983ae2))

## [1.4.0](https://www.github.com/googleapis/python-webrisk/compare/v1.3.0...v1.4.0) (2021-07-01)


### Features

* add always_use_jwt_access ([#96](https://www.github.com/googleapis/python-webrisk/issues/96)) ([b0f0fd3](https://www.github.com/googleapis/python-webrisk/commit/b0f0fd3c7acd0bb4061956c3afd8e50d4d3c63a7))


### Bug Fixes

* disable always_use_jwt_access ([#100](https://www.github.com/googleapis/python-webrisk/issues/100)) ([8f2d77e](https://www.github.com/googleapis/python-webrisk/commit/8f2d77ec058ba0a9943f43edcf077835a6dbd47e))


### Documentation

* omit mention of Python 2.7 in 'CONTRIBUTING.rst' ([#1127](https://www.github.com/googleapis/python-webrisk/issues/1127)) ([#91](https://www.github.com/googleapis/python-webrisk/issues/91)) ([fe10bdc](https://www.github.com/googleapis/python-webrisk/commit/fe10bdc4e887621002230c175f3a93916b6d81ca)), closes [#1126](https://www.github.com/googleapis/python-webrisk/issues/1126)

## [1.3.0](https://www.github.com/googleapis/python-webrisk/compare/v1.2.0...v1.3.0) (2021-06-01)


### Features

* bump release level to production/stable ([#81](https://www.github.com/googleapis/python-webrisk/issues/81)) ([0946b75](https://www.github.com/googleapis/python-webrisk/commit/0946b753e9371a4f275035cf35b11fd6b5b5464e)), closes [#20](https://www.github.com/googleapis/python-webrisk/issues/20)


### Bug Fixes

* **deps:** add packaging requirement ([#82](https://www.github.com/googleapis/python-webrisk/issues/82)) ([4ec0245](https://www.github.com/googleapis/python-webrisk/commit/4ec0245957d14816bd3ed293e617f5cf830850f4))

## [1.2.0](https://www.github.com/googleapis/python-webrisk/compare/v1.1.0...v1.2.0) (2021-03-31)


### Features

* add `from_service_account_info` ([#55](https://www.github.com/googleapis/python-webrisk/issues/55)) ([1e9e2c0](https://www.github.com/googleapis/python-webrisk/commit/1e9e2c0dba40a439727644d623b30ad5f63a0602))

## [1.1.0](https://www.github.com/googleapis/python-webrisk/compare/v1.0.1...v1.1.0) (2021-02-11)


### Features

* add common resource helpers; expose client transport; remove gRPC send/recv limits ([#40](https://www.github.com/googleapis/python-webrisk/issues/40)) ([3f09199](https://www.github.com/googleapis/python-webrisk/commit/3f09199d2a9aa40a74dc7f83ac3d4b27bb4e3791))

### [1.0.1](https://www.github.com/googleapis/python-webrisk/compare/v1.0.0...v1.0.1) (2020-07-15)


### Bug Fixes

* update README for library conversion to microgenerator ([#29](https://www.github.com/googleapis/python-webrisk/issues/29)) ([ebd278b](https://www.github.com/googleapis/python-webrisk/commit/ebd278b8c41d72a9f9c594677c8d69684d8ef977))

## [1.0.0](https://www.github.com/googleapis/python-webrisk/compare/v0.3.0...v1.0.0) (2020-07-14)


### ⚠ BREAKING CHANGES

* move to webrisk API to python microgenerator (#27)

### Features

* move to webrisk API to python microgenerator ([#27](https://www.github.com/googleapis/python-webrisk/issues/27)) ([bbd2adf](https://www.github.com/googleapis/python-webrisk/commit/bbd2adf8e389e211580873b3c7793be08a034fe7))
* release as production/stable ([#19](https://www.github.com/googleapis/python-webrisk/issues/19)) ([a9f7733](https://www.github.com/googleapis/python-webrisk/commit/a9f7733536ee9cd88f471f395353d4991dd8aa62))


### Bug Fixes

* update retry configs ([#24](https://www.github.com/googleapis/python-webrisk/issues/24)) ([6cda903](https://www.github.com/googleapis/python-webrisk/commit/6cda9039c6601fdb5e06870ae282480dc03590f0))


### Documentation

* update docstrings (via synth) ([#14](https://www.github.com/googleapis/python-webrisk/issues/14)) ([327d07a](https://www.github.com/googleapis/python-webrisk/commit/327d07abdf418ae07bad2e66165bb127f599e3e2))

## [0.3.0](https://www.github.com/googleapis/python-webrisk/compare/v0.2.0...v0.3.0) (2020-04-20)


### Features

* add v1 ([#11](https://www.github.com/googleapis/python-webrisk/issues/11)) ([8b1ddd5](https://www.github.com/googleapis/python-webrisk/commit/8b1ddd5beed899ab0d30dbd79282beb0b055c78d))

## 0.2.0

07-24-2019 17:55 PDT


### Implementation Changes
- Allow kwargs to be passed to create_channel (via synth). ([#8412](https://github.com/googleapis/google-cloud-python/pull/8412))

### New Features
- Add 'client_options' support, update list method docstrings (via synth). ([#8530](https://github.com/googleapis/google-cloud-python/pull/8530))

### Dependencies
- Bump minimum version for google-api-core to 1.14.0. ([#8709](https://github.com/googleapis/google-cloud-python/pull/8709))

### Documentation
- Link to googleapis.dev documentation in READMEs. ([#8705](https://github.com/googleapis/google-cloud-python/pull/8705))
- Add compatibility check badges to READMEs. ([#8288](https://github.com/googleapis/google-cloud-python/pull/8288))

### Internal / Testing Changes
- Add docs job to publish to googleapis.dev. ([#8464](https://github.com/googleapis/google-cloud-python/pull/8464))
- Declare encoding as utf-8 in pb2 files (via synth). ([#8372](https://github.com/googleapis/google-cloud-python/pull/8372))
- Add disclaimer to auto-generated template files. ([#8336](https://github.com/googleapis/google-cloud-python/pull/8336))
- Fix coverage in 'types.py' (via synth). ([#8171](https://github.com/googleapis/google-cloud-python/pull/8171))
- Add empty lines (via synth). ([#8078](https://github.com/googleapis/google-cloud-python/pull/8078))

## 0.1.0

04-16-2019 17:09 PDT


### New Features
- Initial release of Web Risk. ([#7651](https://github.com/googleapis/google-cloud-python/pull/7651))

### Documentation
- Add whitelist info to README. ([#7717](https://github.com/googleapis/google-cloud-python/pull/7717))
