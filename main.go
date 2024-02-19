package EmailChecker

import (
	"encoding/json"
	"net"
	"strings"
)

type DomainCheckResult struct {
	Domain       string `json:"domain"`
	MXPresent    bool   `json:"mx_present"`
	SPFPresent   bool   `json:"spf_present"`
	DMARCPresent bool   `json:"dmarc_present"`
	SPFRecord    string `json:"spf_record,omitempty"`
	DMARCRecord  string `json:"dmarc_record,omitempty"`
}

func checkDomain(email string) (string, error) {
	domain := extractDomain(email)
	var result DomainCheckResult

	// Check for MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return "", err
	}
	result.MXPresent = len(mxRecords) > 0

	// Check for SPF records
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return "", err
	}
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			result.SPFPresent = true
			result.SPFRecord = record
			break
		}
	}

	// Check for DMARC records
	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		return "", err
	}
	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			result.DMARCPresent = true
			result.DMARCRecord = record
			break
		}
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "Invalid email format"
	}
	return parts[1]
}
