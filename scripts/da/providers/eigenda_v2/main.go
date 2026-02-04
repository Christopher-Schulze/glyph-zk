package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Layr-Labs/eigenda/api/clients/v2"
	"github.com/Layr-Labs/eigenda/api/clients/v2/coretypes"
	"github.com/Layr-Labs/eigenda/api/clients/v2/payloaddispersal"
	"github.com/Layr-Labs/eigenda/api/clients/v2/payloadretrieval"
	"github.com/Layr-Labs/eigenda/api/clients/v2/relay"
	"github.com/Layr-Labs/eigenda/api/clients/v2/verification"
	dispgrpc "github.com/Layr-Labs/eigenda/api/grpc/disperser/v2"
	"github.com/Layr-Labs/eigenda/common"
	"github.com/Layr-Labs/eigenda/common/geth"
	core "github.com/Layr-Labs/eigenda/core"
	auth "github.com/Layr-Labs/eigenda/core/auth/v2"
	corev2 "github.com/Layr-Labs/eigenda/core/v2"
	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/kzg"
	kzgprover "github.com/Layr-Labs/eigenda/encoding/kzg/prover"
	kzgverifier "github.com/Layr-Labs/eigenda/encoding/kzg/verifier"
	"github.com/Layr-Labs/eigensdk-go/logging"
	gethcommon "github.com/ethereum/go-ethereum/common"
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

func main() {
	mode := flag.String("mode", "", "submit, poll, or fetch")
	payloadPath := flag.String("payload", "", "path to payload file (submit)")
	outPath := flag.String("out", "", "output path (fetch)")
	blobKeyHex := flag.String("blob-key", "", "blob key (0x...)")
	noWait := flag.Bool("no-wait", false, "submit without waiting for completion")
	flag.Parse()

	if *mode != "submit" && *mode != "poll" && *mode != "fetch" {
		die("mode must be submit, poll, or fetch")
	}

	cfg, err := loadConfig()
	if err != nil {
		die(err.Error())
	}

	logger := &noopLogger{}

	ethClient, err := createEthClient(logger, cfg.EthRPCURL)
	if err != nil {
		die(fmt.Sprintf("eth client: %v", err))
	}

	certVerifier, err := verification.NewCertVerifier(
		logger,
		ethClient,
		verification.NewStaticCertVerifierAddressProvider(gethcommon.HexToAddress(cfg.CertVerifierAddr)),
	)
	if err != nil {
		die(fmt.Sprintf("cert verifier: %v", err))
	}

	verifier, err := createKzgVerifier(cfg.SRSDir)
	if err != nil {
		die(fmt.Sprintf("kzg verifier: %v", err))
	}

	prover, err := createKzgProver(cfg.SRSDir)
	if err != nil {
		die(fmt.Sprintf("kzg prover: %v", err))
	}

	disperserClient, err := createDisperserClient(cfg.DisperserAddr, cfg.AuthPrivateKeyHex, prover)
	if err != nil {
		die(fmt.Sprintf("disperser client: %v", err))
	}
	defer disperserClient.Close()

	switch *mode {
	case "submit":
		if *payloadPath == "" {
			die("payload path required for submit")
		}
		data, err := os.ReadFile(*payloadPath)
		if err != nil {
			die(fmt.Sprintf("read payload: %v", err))
		}
		payload := coretypes.NewPayload(data)
		if *noWait {
			blobKey, err := disperseNoWait(disperserClient, certVerifier, payload, cfg)
			if err != nil {
				die(fmt.Sprintf("submit v2 no-wait: %v", err))
			}
			writeJSON(map[string]any{
				"provider":      "eigenda",
				"version":       "v2",
				"status":        "pending",
				"blob_key":      "0x" + blobKey.Hex(),
				"disperser_url": cfg.DisperserAddr,
			})
			return
		}
		cert, err := sendPayloadAndWait(disperserClient, certVerifier, payload, cfg)
		if err != nil {
			die(fmt.Sprintf("submit v2: %v", err))
		}
		blobKey, err := cert.ComputeBlobKey()
		if err != nil {
			die(fmt.Sprintf("compute blob key: %v", err))
		}
		certHash := hashCert(cert)
		writeJSON(map[string]any{
			"provider":         "eigenda",
			"version":          "v2",
			"status":           "complete",
			"blob_key":         "0x" + blobKey.Hex(),
			"certificate_hash": certHash,
			"disperser_url":    cfg.DisperserAddr,
		})
	case "poll":
		if *blobKeyHex == "" {
			die("blob-key required for poll")
		}
		blobKey, err := corev2.HexToBlobKey(*blobKeyHex)
		if err != nil {
			die(fmt.Sprintf("invalid blob key: %v", err))
		}
		cert, status, err := pollUntilComplete(disperserClient, certVerifier, blobKey, cfg)
		if err != nil {
			die(fmt.Sprintf("poll v2: %v", err))
		}
		certHash := hashCert(cert)
		writeJSON(map[string]any{
			"provider":         "eigenda",
			"version":          "v2",
			"status":           status,
			"blob_key":         "0x" + blobKey.Hex(),
			"certificate_hash": certHash,
			"disperser_url":    cfg.DisperserAddr,
		})
	case "fetch":
		if *blobKeyHex == "" {
			die("blob-key required for fetch")
		}
		if *outPath == "" {
			die("out path required for fetch")
		}
		blobKey, err := corev2.HexToBlobKey(*blobKeyHex)
		if err != nil {
			die(fmt.Sprintf("invalid blob key: %v", err))
		}
		cert, _, err := pollUntilComplete(disperserClient, certVerifier, blobKey, cfg)
		if err != nil {
			die(fmt.Sprintf("poll v2: %v", err))
		}
		payload, err := fetchPayload(logger, ethClient, cert, verifier, cfg)
		if err != nil {
			die(fmt.Sprintf("fetch payload: %v", err))
		}
		if err := os.WriteFile(*outPath, payload.Serialize(), 0o644); err != nil {
			die(fmt.Sprintf("write output: %v", err))
		}
		writeJSON(map[string]any{
			"provider":     "eigenda",
			"payload_path": *outPath,
		})
	}
}

type config struct {
	DisperserAddr       string
	EthRPCURL           string
	CertVerifierAddr    string
	RelayRegistryAddr   string
	AuthPrivateKeyHex   string
	SRSDir              string
	BlobVersion         corev2.BlobVersion
	DisperseTimeout     time.Duration
	BlobCompleteTimeout time.Duration
	StatusPollInterval  time.Duration
	ContractCallTimeout time.Duration
	RelayTimeout        time.Duration
}

func loadConfig() (*config, error) {
	cfg := &config{
		DisperserAddr:       os.Getenv("EIGENDA_V2_DISPERSER_ADDR"),
		EthRPCURL:           os.Getenv("EIGENDA_V2_ETH_RPC_URL"),
		CertVerifierAddr:    os.Getenv("EIGENDA_V2_CERT_VERIFIER_ADDR"),
		RelayRegistryAddr:   os.Getenv("EIGENDA_V2_RELAY_REGISTRY_ADDR"),
		AuthPrivateKeyHex:   strings.TrimPrefix(os.Getenv("EIGENDA_V2_AUTH_PRIVATE_KEY_HEX"), "0x"),
		SRSDir:              os.Getenv("EIGENDA_V2_SRS_DIR"),
		BlobVersion:         corev2.BlobVersion(envUint("EIGENDA_V2_BLOB_VERSION", 0)),
		DisperseTimeout:     envDuration("EIGENDA_V2_DISPERSE_TIMEOUT_SEC", 30*time.Second),
		BlobCompleteTimeout: envDuration("EIGENDA_V2_BLOB_COMPLETE_TIMEOUT_SEC", 120*time.Second),
		StatusPollInterval:  envDuration("EIGENDA_V2_STATUS_POLL_SEC", 3*time.Second),
		ContractCallTimeout: envDuration("EIGENDA_V2_CONTRACT_TIMEOUT_SEC", 5*time.Second),
		RelayTimeout:        envDuration("EIGENDA_V2_RELAY_TIMEOUT_SEC", 5*time.Second),
	}
	if cfg.DisperserAddr == "" || cfg.EthRPCURL == "" || cfg.CertVerifierAddr == "" || cfg.AuthPrivateKeyHex == "" {
		return nil, errors.New("missing required EIGENDA_V2 envs")
	}
	if cfg.SRSDir == "" {
		return nil, errors.New("EIGENDA_V2_SRS_DIR not set")
	}
	return cfg, nil
}

func createEthClient(logger logging.Logger, rpc string) (*geth.EthClient, error) {
	ethClientConfig := geth.EthClientConfig{
		RPCURLs:          []string{rpc},
		NumConfirmations: 0,
		NumRetries:       3,
	}
	return geth.NewClient(ethClientConfig, gethcommon.Address{}, 0, logger)
}

func createKzgConfig(srsDir string) kzg.KzgConfig {
	return kzg.KzgConfig{
		G1Path:          filepath.Join(srsDir, "g1.point"),
		G2Path:          filepath.Join(srsDir, "g2.point"),
		G2TrailingPath:  filepath.Join(srsDir, "g2.trailing.point"),
		CacheDir:        filepath.Join(srsDir, "SRSTables"),
		SRSOrder:        268435456,
		SRSNumberToLoad: uint64(1<<13) / encoding.BYTES_PER_SYMBOL,
		NumWorker:       4,
		LoadG2Points:    true,
	}
}

func createKzgVerifier(srsDir string) (*kzgverifier.Verifier, error) {
	cfg := createKzgConfig(srsDir)
	cfg.LoadG2Points = false
	return kzgverifier.NewVerifier(&cfg, nil)
}

func createKzgProver(srsDir string) (*kzgprover.Prover, error) {
	cfg := createKzgConfig(srsDir)
	return kzgprover.NewProver(&cfg, nil)
}

func createDisperserClient(addr string, privKeyHex string, prover *kzgprover.Prover) (clients.DisperserClient, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	signer, err := auth.NewLocalBlobRequestSigner("0x" + privKeyHex)
	if err != nil {
		return nil, err
	}
	cfg := &clients.DisperserClientConfig{
		Hostname:          host,
		Port:              port,
		UseSecureGrpcFlag: true,
	}
	return clients.NewDisperserClient(cfg, signer, prover, nil)
}

func disperseNoWait(dc clients.DisperserClient, cv clients.ICertVerifier, payload *coretypes.Payload, cfg *config) (corev2.BlobKey, error) {
	requiredQuorums, err := cv.GetQuorumNumbersRequired(context.Background())
	if err != nil {
		return corev2.BlobKey{}, err
	}
	quorums := make([]core.QuorumID, len(requiredQuorums))
	for i, q := range requiredQuorums {
		quorums[i] = core.QuorumID(q)
	}
	blob, err := payload.ToBlob(clients.GetDefaultPayloadClientConfig().PayloadPolynomialForm)
	if err != nil {
		return corev2.BlobKey{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DisperseTimeout)
	defer cancel()
	_, blobKey, err := dc.DisperseBlob(ctx, blob.Serialize(), cfg.BlobVersion, quorums)
	if err != nil {
		return corev2.BlobKey{}, err
	}
	return blobKey, nil
}

func sendPayloadAndWait(dc clients.DisperserClient, cv clients.ICertVerifier, payload *coretypes.Payload, cfg *config) (*coretypes.EigenDACert, error) {
	disperserConfig := payloaddispersal.PayloadDisperserConfig{
		PayloadClientConfig:    *clients.GetDefaultPayloadClientConfig(),
		DisperseBlobTimeout:    cfg.DisperseTimeout,
		BlobCompleteTimeout:    cfg.BlobCompleteTimeout,
		BlobStatusPollInterval: cfg.StatusPollInterval,
		ContractCallTimeout:    cfg.ContractCallTimeout,
	}
	pd, err := payloaddispersal.NewPayloadDisperser(&noopLogger{}, disperserConfig, dc, cv, nil)
	if err != nil {
		return nil, err
	}
	return pd.SendPayload(context.Background(), payload)
}

func pollUntilComplete(dc clients.DisperserClient, cv clients.ICertVerifier, blobKey corev2.BlobKey, cfg *config) (*coretypes.EigenDACert, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.BlobCompleteTimeout)
	defer cancel()
	ticker := time.NewTicker(cfg.StatusPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("poll timeout: %w", ctx.Err())
		case <-ticker.C:
			statusRes, err := dc.GetBlobStatus(ctx, blobKey)
			if err != nil {
				continue
			}
			if statusRes.GetStatus() != dispgrpc.BlobStatus_COMPLETE {
				continue
			}
			ns, err := cv.GetNonSignerStakesAndSignature(ctx, statusRes.GetSignedBatch())
			if err != nil {
				return nil, "", err
			}
			cert, err := coretypes.BuildEigenDACert(statusRes, ns)
			if err != nil {
				return nil, "", err
			}
			if err := cv.VerifyCertV2(ctx, cert); err != nil {
				return nil, "", err
			}
			return cert, "complete", nil
		}
	}
}

func fetchPayload(logger logging.Logger, ethClient common.EthClient, cert *coretypes.EigenDACert, verifier *kzgverifier.Verifier, cfg *config) (*coretypes.Payload, error) {
	if cfg.RelayRegistryAddr == "" {
		return nil, errors.New("EIGENDA_V2_RELAY_REGISTRY_ADDR not set")
	}
	relayUrlProvider, err := relay.NewRelayUrlProvider(ethClient, gethcommon.HexToAddress(cfg.RelayRegistryAddr))
	if err != nil {
		return nil, err
	}
	relayClient, err := relay.NewRelayClient(
		&relay.RelayClientConfig{UseSecureGrpcFlag: true, MaxGRPCMessageSize: 100 * 1024 * 1024},
		logger,
		relayUrlProvider,
	)
	if err != nil {
		return nil, err
	}
	defer relayClient.Close()
	retriever, err := payloadretrieval.NewRelayPayloadRetriever(
		logger,
		rand.New(rand.NewSource(time.Now().UnixNano())),
		payloadretrieval.RelayPayloadRetrieverConfig{
			PayloadClientConfig: *clients.GetDefaultPayloadClientConfig(),
			RelayTimeout:        cfg.RelayTimeout,
		},
		relayClient,
		verifier.Srs.G1,
	)
	if err != nil {
		return nil, err
	}
	return retriever.GetPayload(context.Background(), cert)
}

func hashCert(cert *coretypes.EigenDACert) string {
	raw, _ := json.Marshal(cert)
	sum := sha256.Sum256(raw)
	return "0x" + hex.EncodeToString(sum[:])
}

func splitHostPort(addr string) (string, string, error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid host:port: %s", addr)
	}
	return parts[0], parts[1], nil
}

func envDuration(key string, def time.Duration) time.Duration {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	num, err := strconv.ParseInt(val, 10, 64)
	if err != nil || num <= 0 {
		return def
	}
	return time.Duration(num) * time.Second
}

func envUint(key string, def uint16) uint16 {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	num, err := strconv.ParseUint(val, 10, 16)
	if err != nil {
		return def
	}
	return uint16(num)
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
