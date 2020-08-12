package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc/credentials"
)

// HealthStatus is an "enum" to represent the health status of the service
type HealthStatus int32

const (
	// StatusHealthy indicates that everything is fine.
	StatusHealthy = HealthStatus(0)
	// StatusInvalidArguments indicates specified invalid arguments.
	StatusInvalidArguments = HealthStatus(1)
	// StatusConnectionFailure indicates connection failed.
	StatusConnectionFailure = HealthStatus(2)
	// StatusRPCFailure indicates rpc failed.
	StatusRPCFailure = HealthStatus(3)
	// StatusUnhealthy indicates rpc succeeded but indicates unhealthy service.
	StatusUnhealthy = HealthStatus(4)
)

// RunProbe runs the actual probe
func RunProbe(args RunProbeArgs) HealthStatus {
	validArgs := args.Check(func(s string, v ...interface{}) {
		log.Printf("error: "+s, v...)
	})
	if !validArgs {
		return StatusInvalidArguments
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		sig := <-c
		if sig == os.Interrupt {
			log.Printf("cancellation received")
			cancel()
			return
		}
	}()

	opts := []grpc.DialOption{
		grpc.WithUserAgent(args.FlUserAgent),
		grpc.WithBlock()}
	if args.FlTLS {
		creds, err := buildCredentials(args.FlTLSNoVerify, args.FlTLSCACert, args.FlTLSClientCert, args.FlTLSClientKey, args.FlTLSServerName)
		if err != nil {
			log.Printf("failed to initialize tls credentials. error=%v", err)
			return StatusInvalidArguments
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if args.FlVerbose {
		log.Print("establishing connection")
	}
	connStart := time.Now()
	dialCtx, cancel2 := context.WithTimeout(ctx, args.FlConnTimeout)
	defer cancel2()
	conn, err := grpc.DialContext(dialCtx, args.FlAddr, opts...)
	if err != nil {
		if err == context.DeadlineExceeded {
			log.Printf("timeout: failed to connect service %q within %v", args.FlAddr, args.FlConnTimeout)
		} else {
			log.Printf("error: failed to connect service at %q: %+v", args.FlAddr, err)
		}
		return StatusConnectionFailure
	}
	connDuration := time.Since(connStart)
	defer conn.Close()
	if args.FlVerbose {
		log.Printf("connection establisted (took %v)", connDuration)
	}

	rpcStart := time.Now()
	rpcCtx, rpcCancel := context.WithTimeout(ctx, args.FlRPCTimeout)
	defer rpcCancel()
	resp, err := healthpb.NewHealthClient(conn).Check(rpcCtx, &healthpb.HealthCheckRequest{Service: args.FlService})
	if err != nil {
		if stat, ok := status.FromError(err); ok && stat.Code() == codes.Unimplemented {
			log.Printf("error: this server does not implement the grpc health protocol (grpc.health.v1.Health)")
		} else if stat, ok := status.FromError(err); ok && stat.Code() == codes.DeadlineExceeded {
			log.Printf("timeout: health rpc did not complete within %v", args.FlRPCTimeout)
		} else {
			log.Printf("error: health rpc failed: %+v", err)
		}
		return StatusRPCFailure
	}
	rpcDuration := time.Since(rpcStart)

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		log.Printf("service unhealthy (responded with %q)", resp.GetStatus().String())
		return StatusUnhealthy
	}
	if args.FlVerbose {
		log.Printf("time elapsed: connect=%v rpc=%v", connDuration, rpcDuration)
	}
	log.Printf("status: %v", resp.GetStatus())
	return toHealthStatus(resp.GetStatus())
}

// at this point it should always be serving, but just to make sure
func toHealthStatus(s healthpb.HealthCheckResponse_ServingStatus) HealthStatus {
	switch s {
	case healthpb.HealthCheckResponse_UNKNOWN:
		return StatusUnhealthy
	case healthpb.HealthCheckResponse_SERVING:
		return StatusHealthy
	case healthpb.HealthCheckResponse_NOT_SERVING:
		return StatusUnhealthy
	case healthpb.HealthCheckResponse_SERVICE_UNKNOWN:
		return StatusUnhealthy
	default:
		return StatusInvalidArguments
	}
}

func buildCredentials(skipVerify bool, caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls client cert/key pair. error=%v", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	if skipVerify {
		cfg.InsecureSkipVerify = true
	} else if caCerts != "" {
		// override system roots
		rootCAs := x509.NewCertPool()
		pem, err := ioutil.ReadFile(caCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA certificates from file (%s) error=%v", caCerts, err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no root CA certs parsed from file %s", caCerts)
		}
		cfg.RootCAs = rootCAs
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return credentials.NewTLS(&cfg), nil
}
