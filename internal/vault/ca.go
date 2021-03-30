package vault

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/globalsign/est"
	"github.com/go-resty/resty/v2"
	"net/http"
)

type VaultCA struct {
}

const (
	//alphanumerics              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	//bitSizeHeader              = "Bit-Size"
	csrAttrsAPS = "csrattrs"
	//defaultCertificateDuration = time.Hour * 24 * 90
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

	for certPEM, rest := pem.Decode(resp.Body()); certPEM != nil; {
		certDER, err := x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, certDER)
		certPEM, rest = pem.Decode(rest)
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

func (ca *VaultCA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	panic("implement me")
}

func (ca *VaultCA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	panic("implement me")
}

func (ca *VaultCA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	panic("implement me")
}

func (ca *VaultCA) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	panic("implement me")
}
