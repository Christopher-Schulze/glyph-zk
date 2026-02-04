package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Layr-Labs/eigenda/api/clients"
	"github.com/Layr-Labs/eigenda/api/clients/codecs"
	grpcdisperser "github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/Layr-Labs/eigensdk-go/logging"
	"github.com/ethereum/go-ethereum/crypto"
)

type noopLogger struct{}

func (n *noopLogger) Debug(msg string, tags ...any)        {}
func (n *noopLogger) Info(msg string, tags ...any)         {}
func (n *noopLogger) Warn(msg string, tags ...any)         {}
func (n *noopLogger) Error(msg string, tags ...any)        {}
func (n *noopLogger) Fatal(msg string, tags ...any)        {}
func (n *noopLogger) Debugf(t string, args ...interface{}) {}
func (n *noopLogger) Infof(t string, args ...interface{})  {}
func (n *noopLogger) Warnf(t string, args ...interface{})  {}
func (n *noopLogger) Errorf(t string, args ...interface{}) {}
func (n *noopLogger) Fatalf(t string, args ...interface{}) {}
func (n *noopLogger) With(tags ...any) logging.Logger      { return n }

type submitResult struct {
	Provider        string `json:"provider"`
	BlobKey         string `json:"blob_key"`
	CertificateHash string `json:"certificate_hash"`
	DisperserURL    string `json:"disperser_url,omitempty"`
}

type fetchResult struct {
	Provider    string `json:"provider"`
	PayloadPath string `json:"payload_path"`
}

func main() {
	mode := flag.String("mode", "", "submit or fetch")
	payloadPath := flag.String("payload", "", "path to payload file")
	outPath := flag.String("out", "", "path to output file for fetch")
	blobKey := flag.String("blob-key", "", "blob key (batch_header_hash:blob_index)")
	batchHashHex := flag.String("batch-hash", "", "batch header hash hex (0x...)")
	blobIndex := flag.Uint("blob-index", 0, "blob index")
	requestID := flag.String("request-id", "", "request id hex (0x...)")
	noWait := flag.Bool("no-wait", false, "submit without waiting for on-chain inclusion")
	flag.Parse()

	if *mode != "submit" && *mode != "fetch" && *mode != "poll" {
		die("mode must be submit, fetch, or poll")
	}

	cfg, err := loadConfig()
	if err != nil {
		die(err.Error())
	}

	client, err := clients.NewEigenDAClient(&noopLogger{}, cfg)
	if err != nil {
		die(fmt.Sprintf("eigenda client init failed: %v", err))
	}
	defer client.Close()

	switch *mode {
	case "submit":
		if *payloadPath == "" {
			die("payload path required for submit")
		}
		data, err := os.ReadFile(*payloadPath)
		if err != nil {
			die(fmt.Sprintf("read payload: %v", err))
		}
		if *noWait {
			reqID, err := submitNoWait(client, cfg, data)
			if err != nil {
				die(fmt.Sprintf("eigenda submit no-wait: %v", err))
			}
			writeJSON(map[string]any{
				"provider":      "eigenda",
				"version":       "v1",
				"status":        "pending",
				"request_id":    "0x" + hex.EncodeToString(reqID),
				"disperser_url": cfg.RPC,
			})
			return
		}
		ctx := contextWithTimeout(cfg)
		info, err := client.PutBlob(ctx, data)
		if err != nil {
			die(fmt.Sprintf("eigenda put blob: %v", err))
		}
		proof := info.GetBlobVerificationProof()
		if proof == nil || proof.GetBatchMetadata() == nil {
			die("eigenda response missing verification proof metadata")
		}
		batchHash := proof.GetBatchMetadata().GetBatchHeaderHash()
		if len(batchHash) == 0 {
			die("eigenda response missing batch header hash")
		}
		key := fmt.Sprintf("0x%s:%d", hex.EncodeToString(batchHash), proof.GetBlobIndex())
		certHash := certificateHash(batchHash, proof.GetBlobIndex())
		out := submitResult{
			Provider:        "eigenda",
			BlobKey:         key,
			CertificateHash: certHash,
			DisperserURL:    cfg.RPC,
		}
		writeJSON(out)
	case "fetch":
		if *outPath == "" {
			die("out path required for fetch")
		}
		batchHash, idx, err := parseBlobKey(*blobKey, *batchHashHex, *blobIndex)
		if err != nil {
			die(err.Error())
		}
		ctx := contextWithTimeout(cfg)
		data, err := client.GetBlob(ctx, batchHash, idx)
		if err != nil {
			die(fmt.Sprintf("eigenda fetch blob: %v", err))
		}
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			die(fmt.Sprintf("write output: %v", err))
		}
		writeJSON(fetchResult{
			Provider:    "eigenda",
			PayloadPath: *outPath,
		})
	case "poll":
		if *requestID == "" {
			die("request id required for poll")
		}
		reqID, err := parseHexBytes(*requestID)
		if err != nil {
			die(fmt.Sprintf("invalid request id: %v", err))
		}
		status, info, err := pollStatus(client, cfg, reqID)
		if err != nil {
			die(fmt.Sprintf("eigenda poll: %v", err))
		}
		proof := info.GetBlobVerificationProof()
		if proof == nil || proof.GetBatchMetadata() == nil {
			die("eigenda status missing verification proof metadata")
		}
		batchHash := proof.GetBatchMetadata().GetBatchHeaderHash()
		if len(batchHash) == 0 {
			die("eigenda status missing batch header hash")
		}
		key := fmt.Sprintf("0x%s:%d", hex.EncodeToString(batchHash), proof.GetBlobIndex())
		certHash := certificateHash(batchHash, proof.GetBlobIndex())
		writeJSON(map[string]any{
			"provider":         "eigenda",
			"version":          "v1",
			"status":           status,
			"request_id":       "0x" + hex.EncodeToString(reqID),
			"blob_key":         key,
			"certificate_hash": certHash,
			"disperser_url":    cfg.RPC,
		})
	}
}

func loadConfig() (clients.EigenDAClientConfig, error) {
	rpc := os.Getenv("EIGENDA_V1_DISPERSER_ADDR")
	ethRPC := os.Getenv("EIGENDA_V1_ETH_RPC_URL")
	svcMgr := os.Getenv("EIGENDA_V1_SVC_MANAGER_ADDR")
	signer := os.Getenv("EIGENDA_V1_SIGNER_PRIVATE_KEY_HEX")
	disableTLS := envBool("EIGENDA_V1_DISABLE_TLS", false)
	waitFinal := envBool("EIGENDA_V1_WAIT_FOR_FINALIZATION", false)
	confirmDepth := envUint64("EIGENDA_V1_CONFIRMATION_DEPTH", 1)
	responseTimeout := envDuration("EIGENDA_V1_RESPONSE_TIMEOUT_SEC", 30*time.Second)
	confirmTimeout := envDuration("EIGENDA_V1_CONFIRMATION_TIMEOUT_SEC", 15*time.Minute)
	statusTimeout := envDuration("EIGENDA_V1_STATUS_TIMEOUT_SEC", 25*time.Minute)
	statusRetry := envDuration("EIGENDA_V1_STATUS_RETRY_SEC", 5*time.Second)
	disablePointVerify := envBool("EIGENDA_V1_DISABLE_POINT_VERIFY", false)

	if rpc == "" {
		return clients.EigenDAClientConfig{}, errors.New("EIGENDA_V1_DISPERSER_ADDR not set")
	}
	if ethRPC == "" {
		return clients.EigenDAClientConfig{}, errors.New("EIGENDA_V1_ETH_RPC_URL not set")
	}
	if svcMgr == "" {
		return clients.EigenDAClientConfig{}, errors.New("EIGENDA_V1_SVC_MANAGER_ADDR not set")
	}

	return clients.EigenDAClientConfig{
		RPC:                          rpc,
		ResponseTimeout:              responseTimeout,
		ConfirmationTimeout:          confirmTimeout,
		StatusQueryTimeout:           statusTimeout,
		StatusQueryRetryInterval:     statusRetry,
		EthRpcUrl:                    ethRPC,
		SvcManagerAddr:               svcMgr,
		WaitForConfirmationDepth:     confirmDepth,
		WaitForFinalization:          waitFinal,
		CustomQuorumIDs:              nil,
		SignerPrivateKeyHex:          strings.TrimPrefix(signer, "0x"),
		DisableTLS:                   disableTLS,
		PutBlobEncodingVersion:       codecs.PayloadEncodingVersion(0),
		DisablePointVerificationMode: disablePointVerify,
	}, nil
}

func contextWithTimeout(cfg clients.EigenDAClientConfig) context.Context {
	timeout := cfg.StatusQueryTimeout
	if timeout <= 0 {
		timeout = 25 * time.Minute
	}
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return ctx
}

func parseBlobKey(key, batchHashHex string, blobIndex uint) ([]byte, uint32, error) {
	if key != "" {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			return nil, 0, fmt.Errorf("invalid blob_key format: %s", key)
		}
		batchHashHex = parts[0]
		idx, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid blob index in blob_key: %v", err)
		}
		blobIndex = uint(idx)
	}
	if batchHashHex == "" {
		return nil, 0, errors.New("batch header hash not provided")
	}
	batchHashHex = strings.TrimPrefix(batchHashHex, "0x")
	raw, err := hex.DecodeString(batchHashHex)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid batch header hash: %v", err)
	}
	return raw, uint32(blobIndex), nil
}

func certificateHash(batchHeaderHash []byte, blobIndex uint32) string {
	indexBytes := []byte{
		byte(blobIndex >> 24),
		byte(blobIndex >> 16),
		byte(blobIndex >> 8),
		byte(blobIndex),
	}
	buf := append(batchHeaderHash, indexBytes...)
	hash := crypto.Keccak256(buf)
	return "0x" + hex.EncodeToString(hash)
}

func submitNoWait(client *clients.EigenDAClient, cfg clients.EigenDAClientConfig, raw []byte) ([]byte, error) {
	if client.GetCodec() == nil {
		return nil, errors.New("codec not initialized")
	}
	encoded, err := client.GetCodec().EncodeBlob(raw)
	if err != nil {
		return nil, fmt.Errorf("encode blob: %w", err)
	}
	customQuorumNumbers := make([]uint8, len(cfg.CustomQuorumIDs))
	for i, e := range cfg.CustomQuorumIDs {
		customQuorumNumbers[i] = uint8(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ResponseTimeout)
	defer cancel()
	_, requestID, err := client.Client.DisperseBlobAuthenticated(ctx, encoded, customQuorumNumbers)
	if err != nil {
		return nil, err
	}
	return requestID, nil
}

func pollStatus(client *clients.EigenDAClient, cfg clients.EigenDAClientConfig, requestID []byte) (string, *grpcdisperser.BlobInfo, error) {
	timeout := cfg.StatusQueryTimeout
	if timeout <= 0 {
		timeout = 25 * time.Minute
	}
	interval := cfg.StatusQueryRetryInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", nil, fmt.Errorf("poll timeout: %w", ctx.Err())
		case <-ticker.C:
			statusRes, err := client.Client.GetBlobStatus(ctx, requestID)
			if err != nil {
				continue
			}
			switch statusRes.GetStatus() {
			case grpcdisperser.BlobStatus_CONFIRMED:
				return "confirmed", statusRes.GetInfo(), nil
			case grpcdisperser.BlobStatus_FINALIZED:
				return "finalized", statusRes.GetInfo(), nil
			case grpcdisperser.BlobStatus_FAILED:
				return "failed", nil, errors.New("eigenda status failed")
			}
		}
	}
}

func parseHexBytes(raw string) ([]byte, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if s == "" {
		return nil, errors.New("empty hex")
	}
	return hex.DecodeString(s)
}

func envBool(key string, def bool) bool {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envUint64(key string, def uint64) uint64 {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	num, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return def
	}
	return num
}

func envDuration(key string, def time.Duration) time.Duration {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	num, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return def
	}
	if num <= 0 {
		return def
	}
	return time.Duration(num) * time.Second
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(v); err != nil {
		die(fmt.Sprintf("encode json: %v", err))
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
