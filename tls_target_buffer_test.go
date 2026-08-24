package reality

import "testing"

// The buffer that holds one record read from the borrowed target must not be
// smaller than a record the target is allowed to send. RFC 8446 §5.2 caps
// TLSCiphertext.length at 2^14 + 256; add the 5-byte record header and that is
// the floor.
//
// This test exists because the value was 8192 for a long time, and the failure it
// caused is the kind nobody catches by looking: the client finishes REALITY
// authentication, then the handshake dies before the inner protocol starts. The
// server logs nothing unusual. www.microsoft.com with OCSP stapling sends a
// Certificate record of 8273 bytes and reproduces it every time.
func TestTargetBufferHoldsAMaximumSizedRecord(t *testing.T) {
	floor := recordHeaderLen + maxCiphertextTLS13
	if size < floor {
		t.Fatalf(
			"target read buffer is %d bytes, below the %d-byte TLS 1.3 record ceiling; "+
				"targets with large certificate chains will be abandoned after the client authenticates",
			size, floor,
		)
	}
	if len(empty) != size {
		t.Fatalf("empty buffer is %d bytes but size is %d; they must track each other", len(empty), size)
	}
}

// A record longer than the protocol allows is still rejected — widening the
// buffer to the RFC bound must not turn into "accept anything".
func TestTargetBufferDoesNotExceedTheProtocolCeiling(t *testing.T) {
	ceiling := recordHeaderLen + maxCiphertextTLS13
	if size > ceiling {
		t.Fatalf(
			"target read buffer is %d bytes, above the %d-byte ceiling; "+
				"nothing legitimate is that large, so the extra room only hides protocol violations",
			size, ceiling,
		)
	}
}
