package vault

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/globalsign/est"
	"github.com/go-resty/resty/v2"
	"net/http"
	"strconv"
	"time"
)

type VaultCA struct {
}

type CommonCAResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
}

type SignResponse struct {
	CommonCAResponse
	Data *SignResponseData `json:"data"`
}

type CertResponse struct {
	CommonCAResponse
	Data *CertRespData `json:"data"`
}

type SignResponseData struct {
	Certificate  string   `json:"certificate"`
	IssuingCA    string   `json:"issuing_ca"`
	CAChain      []string `json:"ca_chain"`
	SerialNumber string   `json:"serial_number"`
}

type CertRespData struct {
	SignResponseData
	PrivateKey     string `json:"private_key"`
	PrivateKeyType string `json:"private_key_type"`
}

const (
	//alphanumerics              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bitSizeHeader              = "Bit-Size"
	csrAttrsAPS                = "csrattrs"
	defaultCertificateDuration = time.Hour * 24 * 90
	//serverKeyGenPassword       = "pseudohistorical"
	//rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS = "triggererrors"
)

// CACerts returns the CA certificates, unless the additional path segment is
// "triggererrors", in which case an error is returned for testing purposes.
func (ca *VaultCA) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	client := resty.New()

	resp, err := client.R().
		EnableTrace().
		Get("http://localhost:8200/v1/pki/ca_chain")

	if err != nil {
		return nil, fmt.Errorf("failed to request to CA server: %w", err)
	}

	var certs []*x509.Certificate

	for certDER, rest := pem.Decode(resp.Body()); certDER != nil; {
		cert, err := x509.ParseCertificate(certDER.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
		certDER, rest = pem.Decode(rest)
	}

	return certs, nil
}

// CSRAttrs returns an empty sequence of CSR attributes, unless the additional
// path segment is:
//  - "csrattrs", in which case it returns the same example sequence described
//    in RFC7030 4.5.2; or
//  - "triggererrors", in which case an error is returned for testing purposes.
func (ca *VaultCA) CSRAttrs(ctx context.Context, aps string, r *http.Request) (attrs est.CSRAttrs, err error) {
	switch aps {
	case csrAttrsAPS:
		attrs = est.CSRAttrs{
			OIDs: []asn1.ObjectIdentifier{
				{1, 2, 840, 113549, 1, 9, 7},
				{1, 2, 840, 10045, 4, 3, 3},
			},
			Attributes: []est.Attribute{
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
				},
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
				},
			},
		}

	case triggerErrorsAPS:
		err = errors.New("triggered error")
	}

	return attrs, err
}

// Enroll issues a new certificate with:
//   - a 90 day duration from the current time
//   - a randomly generated 128-bit serial number
//   - a subject and subject alternative name copied from the provided CSR
//   - a default set of key usages and extended key usages
//   - a basic constraints extension with cA flag set to FALSE
//
// unless the additional path segment is "triggererrors", in which case the
// following errors will be returned for testing purposes, depending on the
// common name in the CSR:
//
//   - "Trigger Error Forbidden", HTTP status 403
//   - "Trigger Error Deferred", HTTP status 202 with retry of 600 seconds
//   - "Trigger Error Unknown", untyped error expected to be interpreted as
//     an internal server error.
func (ca *VaultCA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	client := resty.New()

	var buf bytes.Buffer
	b := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}

	if err := pem.Encode(&buf, b); err != nil {
		return nil, fmt.Errorf("failed to encode pem: %w", err)
	}

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Vault-Token", "s.2KK80gQfdiNldooflo4YB3sk").
		SetBody(fmt.Sprintf(`{"csr": %q}`, buf.String())).
		SetResult(&SignResponse{}).
		Post("http://localhost:8200/v1/pki/sign/est-server")

	if err != nil {
		return nil, fmt.Errorf("failed to request to CA server: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("request rejected by CA server: %s", resp.String())
	}

	signRes := resp.Result().(*SignResponse)

	b, _ = pem.Decode([]byte(signRes.Data.Certificate))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Reenroll implements est.CA but simply passes the request through to Enroll.
func (ca *VaultCA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return ca.Enroll(ctx, csr, aps, r)
}

// ServerKeyGen creates a new RSA private key and then calls Enroll. It returns
// the key in PKCS8 DER-encoding, unless the additional path segment is set to
// "pkcs7", in which case it is returned wrapped in a CMS SignedData structure
// signed by the CA certificate(s), itself wrapped in a CMS EnvelopedData
// encrypted with the pre-shared key "pseudohistorical". A "Bit-Size" HTTP
// header may be passed with the values 2048, 3072 or 4096.
func (ca *VaultCA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	bitsize := 2048
	if r != nil && r.Header != nil {
		if v := r.Header.Get(bitSizeHeader); v != "" {
			var err error
			bitsize, err = strconv.Atoi(v)
			if err != nil || (bitsize != 2048 && bitsize != 3072 && bitsize != 4096) {
				return nil, nil, caError{
					status: http.StatusBadRequest,
					desc:   "invalid bit size value",
				}
			}
		}
	}

	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, nil, errors.New("triggered error")
		}
	}

	// Generate new key.
	client := resty.New()
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Vault-Token", "s.v8DL6ATponhvlTd1lY3x0aCa").
		SetBody(fmt.Sprintf(`{"common_name": %q, "private_key_format": "pkcs8"}`, csr.Subject.CommonName)).
		SetResult(&CertResponse{}).
		Post("http://localhost:8200/v1/pki/issue/est-server-rsa-" + strconv.Itoa(bitsize))

	if err != nil {
		return nil, nil, fmt.Errorf("failed to request to CA server: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, nil, fmt.Errorf("request rejected by CA server: %s", resp.String())
	}

	// Copy raw subject and raw SubjectAltName extension from client CSR into
	// a new CSR signed by the new private key.
	//tmpl := &x509.CertificateRequest{
	//	RawSubject: csr.RawSubject,
	//}
	//
	//for _, ext := range csr.Extensions {
	//	if ext.Id.Equal(oidSubjectAltName) {
	//		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	//		break
	//	}
	//}

	if aps == "pkcs7" {
		return nil, nil, fmt.Errorf("pkcs#7 not supported")
	}

	certResp := resp.Result().(*CertResponse)

	b, _ := pem.Decode([]byte(certResp.Data.Certificate))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	b, _ = pem.Decode([]byte(certResp.Data.PrivateKey))

	return cert, b.Bytes, nil
}

func (ca *VaultCA) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	panic("implement me")
}
