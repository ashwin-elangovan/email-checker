# emailchecker

This Go package, emailchecker, checks the DNS records for a given domain extracted from an email address and displays information about its MX, SPF, and DMARC records.

MX (Mail Exchange) records: MX records specify the mail servers responsible for receiving email for a particular domain.

SPF (Sender Policy Framework): SPF is an email authentication protocol used to prevent email spoofing by specifying which mail servers are authorized to send emails on behalf of a domain.

DMARC (Domain-based Message Authentication, Reporting, and Conformance): DMARC helps prevent email spoofing and phishing attacks by providing a framework for email senders to define how their emails should be handled if they fail authentication checks.


## Usage
```
import (
  emailchecker "github.com/ashwin-elangovan/email-checker"
)

emailchecker.CheckDomain(email)
```

## Response

```
{
"domain":"pm.me",
"mx_present":true,
"spf_present":true,
"dmarc_present":true,
"spf_record":"v=spf1 include:_spf.protonmail.ch ~all",
"dmarc_record":"v=DMARC1; p=quarantine; fo=1; aspf=s; adkim=s;"
}
```
