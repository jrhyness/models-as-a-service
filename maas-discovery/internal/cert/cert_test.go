package cert_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opendatahub-io/models-as-a-service/maas-discovery/internal/cert"
)

func TestGenerate(t *testing.T) {
	tlsCert, err := cert.Generate("test-discovery")
	require.NoError(t, err)
	require.NotEmpty(t, tlsCert.Certificate)

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, []string{"test-discovery"}, leaf.Subject.Organization)
	assert.Equal(t, x509.SHA256WithRSA, leaf.SignatureAlgorithm)
	assert.True(t, leaf.NotAfter.After(time.Now().Add(cert.Duration)))
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}
