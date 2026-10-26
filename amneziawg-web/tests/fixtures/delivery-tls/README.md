# Local TLS rejection fixture

`certificate.der` and `key.der` are a disposable, self-signed localhost identity,
generated solely for the loopback SMTP certificate-rejection test. The private
key is intentionally public test data. It must never be trusted or deployed.

Generated with OpenSSL RSA-2048 / SHA-256, SAN `DNS:localhost`, using `req -x509`
and PKCS#8 DER conversion. The client uses the normal public WebPKI roots; it
must reject this certificate without a trust-store or verification override.

`server.der` is a CA:FALSE self-signed localhost certificate using the same public
fixture key, for a separate loopback connection-check/auth test. Only that test
adds it to its local TLS root set; hostname/certificate checks remain enabled.
It is not a production trust-store change. The fixture asserts EHLO/AUTH/NOOP/
QUIT only and never submits a message; an authentication rejection is sanitized.
