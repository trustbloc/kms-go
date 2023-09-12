[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/kms-crypto-go/main/LICENSE)
[![Release](https://img.shields.io/github/release/trustbloc/kms-crypto-go.svg?style=flat-square)](https://github.com/trustbloc/kms-crypto-go/releases/latest)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/kms-crypto-go)

[![Build Status](https://github.com/trustbloc/kms-crypto-go/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/kms-crypto-go/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/kms-crypto-go)](https://goreportcard.com/report/github.com/trustbloc/kms-crypto-go)


# TrustBloc KMS Go Library

The TrustBloc KMS Go repo contains APIs for Key Management Services (KMS) and Crypto functions.

The Key Management Service(KMS) module has the following implementations.
- LocalKMS: Go KMS implementation to use API consumer-specified storage provider
- WebKMS: Go client for remote KMS implementing [W3C-CCG WebKMS](https://w3c-ccg.github.io/webkms/) standard

The Crypto module has the following implementations.
- tinkcrypto: Wrapper on top of [Google Tink library](https://github.com/google/tink/)
- WebKMS: Go client to interact with the KMS server


## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
