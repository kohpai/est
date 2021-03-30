package vault

import (
	"context"
	"crypto/x509"
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
	//csrAttrsAPS                = "csrattrs"
	//defaultCertificateDuration = time.Hour * 24 * 90
	//serverKeyGenPassword       = "pseudohistorical"
	//rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS = "triggererrors"
)

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

func (ca *VaultCA) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	panic("implement me")
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
