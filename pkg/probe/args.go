package probe

import "time"

// RunProbeArgs are the arguments needed for running the probe
type RunProbeArgs struct {
	FlAddr          string
	FlService       string
	FlUserAgent     string
	FlConnTimeout   time.Duration
	FlRPCTimeout    time.Duration
	FlTLS           bool
	FlTLSNoVerify   bool
	FlTLSCACert     string
	FlTLSClientCert string
	FlTLSClientKey  string
	FlTLSServerName string
	FlVerbose       bool
}

// NewRunProbeArgs creates RunProbeArgs with reasonable default values
func NewRunProbeArgs(flAddr string, flVerbose bool) RunProbeArgs {
	args := RunProbeArgs{
		FlAddr:          flAddr,
		FlService:       "",
		FlUserAgent:     "grpc_health_probe",
		FlConnTimeout:   time.Second,
		FlRPCTimeout:    time.Second,
		FlTLS:           false,
		FlTLSNoVerify:   false,
		FlTLSCACert:     "",
		FlTLSClientCert: "",
		FlTLSClientKey:  "",
		FlTLSServerName: "",
		FlVerbose:       flVerbose,
	}

	return args
}

// Check checks if the arguments are consistent and reasonable
func (args RunProbeArgs) Check(onError func(s string, v ...interface{})) bool {
	if args.FlAddr == "" {
		onError("-addr not specified")
		return false
	}
	if args.FlConnTimeout <= 0 {
		onError("-connect-timeout must be greater than zero (specified: %v)", args.FlConnTimeout)
		return false
	}
	if args.FlRPCTimeout <= 0 {
		onError("-rpc-timeout must be greater than zero (specified: %v)", args.FlRPCTimeout)
		return false
	}
	if !args.FlTLS && args.FlTLSNoVerify {
		onError("specified -tls-no-verify without specifying -tls")
		return false
	}
	if !args.FlTLS && args.FlTLSCACert != "" {
		onError("specified -tls-ca-cert without specifying -tls")
		return false
	}
	if !args.FlTLS && args.FlTLSClientCert != "" {
		onError("specified -tls-client-cert without specifying -tls")
		return false
	}
	if !args.FlTLS && args.FlTLSServerName != "" {
		onError("specified -tls-server-name without specifying -tls")
		return false
	}
	if args.FlTLSClientCert != "" && args.FlTLSClientKey == "" {
		onError("specified -tls-client-cert without specifying -tls-client-key")
		return false
	}
	if args.FlTLSClientCert == "" && args.FlTLSClientKey != "" {
		onError("specified -tls-client-key without specifying -tls-client-cert")
		return false
	}
	if args.FlTLSNoVerify && args.FlTLSCACert != "" {
		onError("cannot specify -tls-ca-cert with -tls-no-verify (CA cert would not be used)")
		return false
	}
	if args.FlTLSNoVerify && args.FlTLSServerName != "" {
		onError("cannot specify -tls-server-name with -tls-no-verify (server name would not be used)")
		return false
	}

	return true
}
