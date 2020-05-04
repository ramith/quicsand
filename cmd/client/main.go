package main

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "flag"
    "github.com/lucas-clemente/quic-go/http3"
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path"
    "sync"
)

func main() {
    verbose := flag.Bool("v", false, "verbose")
    quiet := flag.Bool("q", false, "don't print the data")
    insecure := flag.Bool("insecure", false, "skip certificate verification")

    flag.Parse()
    urls := flag.Args()

    logger, err := NewLogger(*verbose)
    if err != nil {
        log.Fatalf("Error building logger: %s", err.Error())
    }
    defer logger.Sync()

    pool, err := x509.SystemCertPool()
    if err != nil {
        logger.Fatalw("unable to read certs", "err", err)
    }
    AddRootCA(pool)

    roundTripper := &http3.RoundTripper{
        TLSClientConfig: &tls.Config{
            RootCAs:            pool,
            InsecureSkipVerify: *insecure,
            KeyLogWriter:       nil,
        },
        QuicConfig: nil,
    }
    defer roundTripper.Close()
    hclient := &http.Client{
        Transport: roundTripper,
    }

    var wg sync.WaitGroup
    wg.Add(len(urls))
    for _, u := range urls {
        logger.Infow("accessing url", "url", u)
        go func(url string) {
            response, err := hclient.Get(url)
            if err != nil {
                logger.Fatalw("unable to get the url", "url", url, "error", err)
            }
            logger.Infow("response received", "url", url, "response", response)
            body := &bytes.Buffer{}
            _, err = io.Copy(body, response.Body)
            if err != nil {
                logger.Fatalw("unable to response body", "error", err)
            }
            if *quiet {
                logger.Infow("request body bytes", "length", body.Len())
            } else {
                logger.Infof("request body", "body", body.Bytes())
            }
            wg.Done()
        }(u)
    }
    wg.Wait()
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
    currentDir, _ := os.Getwd()
    caCertPath := path.Join(currentDir, "security", "ca.pem")
    caCertRaw, err := ioutil.ReadFile(caCertPath)
    if err != nil {
        panic(err)
    }
    if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
        panic("could not add root certificate to pool.")
    }
}

func NewLogger(verbose bool) (*zap.SugaredLogger, error) {
    var config zap.Config
    if verbose {
        config = zap.NewDevelopmentConfig()
    } else {
        config = zap.NewProductionConfig()
    }
    config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
    logger, err := config.Build()
    if err != nil {
        return nil, err
    }
    return logger.Sugar(), nil
}
