package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	patch1 string = `[
         { "op": "add", "path": "/data/mutation-stage-1", "value": "yes" }
     ]`
)

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func mutateCRD(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	log.Info("mutating crd")

	var cr v1.ConfigMap
	if err := json.Unmarshal(ar.Request.Object.Raw, &cr); err != nil {
		log.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := v1beta1.AdmissionResponse{Allowed: true}
	if cr.Data["mutate"] == "yes" {
		pt := v1beta1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
		reviewResponse.Patch = []byte(patch1)
	}
	return &reviewResponse
}

func validateCRD(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	log.Info("validating CRD")

	var cr v1.ConfigMap
	if err := json.Unmarshal(ar.Request.Object.Raw, &cr); err != nil {
		log.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := v1beta1.AdmissionResponse{Allowed: true}
	if cr.Data["validate"] == "yes" {
		reviewResponse.Allowed = false
		reviewResponse.Result = &metav1.Status{
			Reason: "the custom resource contains unwanted data",
		}
	}
	return &reviewResponse
}

type admitFunc func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

func serve(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		log.Error(err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = admit(ar)
	}

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		response.Response.UID = ar.Request.UID
	}
	// reset the Object and OldObject, they are not needed in a response.
	ar.Request.Object = runtime.RawExtension{}
	ar.Request.OldObject = runtime.RawExtension{}

	resp, err := json.Marshal(response)
	if err != nil {
		log.Error(err)
	}
	if _, err := w.Write(resp); err != nil {
		log.Error(err)
	}
}

func serveMutateCRD(w http.ResponseWriter, r *http.Request) {
	serve(w, r, mutateCRD)
}

func serveValidateCRD(w http.ResponseWriter, r *http.Request) {
	serve(w, r, validateCRD)
}

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)

	certFile string
	keyFile  string
)

func init() {
	corev1.AddToScheme(scheme)
	admissionregistrationv1beta1.AddToScheme(scheme)

	flag.StringVar(&certFile, "tls-cert-file", "", ""+
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated "+
		"after server cert).")
	flag.StringVar(&keyFile, "tls-private-key-file", "", ""+
		"File containing the default x509 private key matching --tls-cert-file.")

	log.SetOutput(os.Stdout)
}

func main() {
	flag.Parse()

	switch {
	case certFile == "":
		log.Error("--tls-cert-file not set")
		os.Exit(1)
	case keyFile == "":
		log.Error("--tls-private-key-file not set")
		os.Exit(1)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Error("could not load key pair from %q and %q: %v", certFile, keyFile)
		os.Exit(1)
	}

	http.HandleFunc("/mutate-crd", serveMutateCRD)
	http.HandleFunc("/validate-crd", serveValidateCRD)

	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,

			// TODO: uses mutual tls after k8s agrees on what cert the
			// apiserver should use.
			// ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}
	server.ListenAndServeTLS("", "")
}
