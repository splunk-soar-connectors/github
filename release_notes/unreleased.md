**Unreleased**

* Breaking change: The `make request` action now verifies TLS certificates by default. Trust the endpoint certificate chain, or explicitly set `verify_ssl` to `false` for endpoints using untrusted certificates.
* Breaking change: Replace Python 3.14 support with Python 3.15, while retaining Python 3.13 support.
* Fix intermittent SOAR authentication timeouts by updating the Splunk SOAR SDK to 7.1.2. [SOARHELP-7374]
