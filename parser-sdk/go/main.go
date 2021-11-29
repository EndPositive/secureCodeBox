// SPDX-FileCopyrightText: 2021 iteratec GmbH
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	executionv1 "github.com/secureCodeBox/secureCodeBox/operator/apis/execution/v1"
	parsertypes "github.com/secureCodeBox/secureCodeBox/parser-sdk/go/types"
	"io"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

var kClient client.Client

func extractScan() (*executionv1.Scan, error) {
	var scan executionv1.Scan
	err := kClient.Get(context.Background(),
		types.NamespacedName{
			Name:      os.Getenv("SCAN_NAME"),
			Namespace: os.Getenv("NAMESPACE"),
		},
		&scan,
	)
	if err != nil {
		return nil, err
	}

	return &scan, nil
}

func parse(io.ReadCloser, *executionv1.Scan) (*[]*parsertypes.Finding, error) {
	var findings []*parsertypes.Finding
	identifiedAt, err := time.Parse(time.RFC3339, "2021-06-22T12:26:54.378Z")
	if err != nil {
		log.Fatal(err)
	}

	URL, err := url.Parse("tcp://127.0.0.1:3306")
	if err != nil {
		log.Fatal(err)
	}

	findings = append(findings, &parsertypes.Finding{
		ID:           uuid.New(),
		Name:         "Open mysql Port",
		Description:  "Port 3306 is open using tcp protocol.",
		Category:     "Open Port",
		IdentifiedAt: identifiedAt,
		Severity:     "INFORMATIONAL",
		Location:     *URL,
	})
	return &findings, nil
}

func addIdsAndDates(findings *[]*parsertypes.Finding) {
	for _, finding := range *findings {
		finding.ID = uuid.New()
		finding.ParsedAt = time.Now()
	}
}

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	kClient, err = client.New(config, client.Options{})
	if err != nil {
		log.Fatal(err)
	}

	scan, err := extractScan()
	if err != nil {
		log.Fatal(err)
	}

	resultFileUrl := os.Args[2]

	response, err := http.Get(resultFileUrl)
	if err != nil {
		log.Fatal(err)
	}
	data := response.Body

	findings, err := parse(data, scan)
	if err != nil {
		log.Fatal(err)
	}
	addIdsAndDates(findings)
	validate := validator.New()
	for _, finding := range *findings {
		err = validate.Struct(finding)
		if err != nil {
			log.Fatal(errors.Wrapf(err, "Finding not valid: %+v", finding))
		}
	}

	b, err := json.Marshal(findings)

	resultUploadUrl := os.Args[3]

	req, err := http.NewRequest("PUT", resultUploadUrl, bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}

	httpClient := &http.Client{}

	res, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		err := errors.Errorf("File upload returned non 2xx status code (%d)", res.StatusCode)

		d, err := httputil.DumpResponse(res, true)
		if err != nil {
			log.Fatal(errors.Wrap(err, "Failed to dump out failed requests to upload scan report to the s3 bucket"))
		}

		log.Println("Failed Request:")
		log.Fatal(string(d))
	}

	return
}
