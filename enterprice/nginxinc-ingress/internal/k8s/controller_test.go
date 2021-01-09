package k8s

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginxinc/kubernetes-ingress/internal/configs"
	"github.com/nginxinc/kubernetes-ingress/internal/configs/version1"
	"github.com/nginxinc/kubernetes-ingress/internal/configs/version2"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/secrets"
	"github.com/nginxinc/kubernetes-ingress/internal/metrics/collectors"
	"github.com/nginxinc/kubernetes-ingress/internal/nginx"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	conf_v1alpha1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	api_v1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestHasCorrectIngressClass(t *testing.T) {
	ingressClass := "ing-ctrl"
	incorrectIngressClass := "gce"
	emptyClass := ""

	var testsWithoutIngressClassOnly = []struct {
		lbc      *LoadBalancerController
		ing      *networking.Ingress
		expected bool
	}{
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: false,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: emptyClass},
				},
			},
			true,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: false,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: incorrectIngressClass},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: false,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: ingressClass},
				},
			},
			true,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: false,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			true,
		},
	}

	var testsWithIngressClassOnly = []struct {
		lbc      *LoadBalancerController
		ing      *networking.Ingress
		expected bool
	}{
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: emptyClass},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: incorrectIngressClass},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: ingressClass},
				},
			},
			true,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true,
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true, // always true for k8s >= 1.18
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &incorrectIngressClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true, // always true for k8s >= 1.18
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &emptyClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true, // always true for k8s >= 1.18
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{ingressClassKey: incorrectIngressClass},
				},
				Spec: networking.IngressSpec{
					IngressClassName: &ingressClass,
				},
			},
			false,
		},
		{
			&LoadBalancerController{
				ingressClass:        ingressClass,
				useIngressClassOnly: true, // always true for k8s >= 1.18
				metricsCollector:    collectors.NewControllerFakeCollector(),
			},
			&networking.Ingress{
				Spec: networking.IngressSpec{
					IngressClassName: &ingressClass,
				},
			},
			true,
		},
	}

	for _, test := range testsWithoutIngressClassOnly {
		if result := test.lbc.HasCorrectIngressClass(test.ing); result != test.expected {
			classAnnotation := "N/A"
			if class, exists := test.ing.Annotations[ingressClassKey]; exists {
				classAnnotation = class
			}
			t.Errorf("lbc.HasCorrectIngressClass(ing), lbc.ingressClass=%v, lbc.useIngressClassOnly=%v, ing.Annotations['%v']=%v; got %v, expected %v",
				test.lbc.ingressClass, test.lbc.useIngressClassOnly, ingressClassKey, classAnnotation, result, test.expected)
		}
	}

	for _, test := range testsWithIngressClassOnly {
		if result := test.lbc.HasCorrectIngressClass(test.ing); result != test.expected {
			classAnnotation := "N/A"
			if class, exists := test.ing.Annotations[ingressClassKey]; exists {
				classAnnotation = class
			}
			t.Errorf("lbc.HasCorrectIngressClass(ing), lbc.ingressClass=%v, lbc.useIngressClassOnly=%v, ing.Annotations['%v']=%v; got %v, expected %v",
				test.lbc.ingressClass, test.lbc.useIngressClassOnly, ingressClassKey, classAnnotation, result, test.expected)
		}
	}

}

func TestHasCorrectIngressClassVS(t *testing.T) {
	ingressClass := "ing-ctrl"
	lbcIngOnlyTrue := &LoadBalancerController{
		ingressClass:        ingressClass,
		useIngressClassOnly: true,
		metricsCollector:    collectors.NewControllerFakeCollector(),
	}

	var testsWithIngressClassOnlyVS = []struct {
		lbc      *LoadBalancerController
		ing      *conf_v1.VirtualServer
		expected bool
	}{
		{
			lbcIngOnlyTrue,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: "",
				},
			},
			true,
		},
		{
			lbcIngOnlyTrue,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: "gce",
				},
			},
			false,
		},
		{
			lbcIngOnlyTrue,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: ingressClass,
				},
			},
			true,
		},
		{
			lbcIngOnlyTrue,
			&conf_v1.VirtualServer{},
			true,
		},
	}

	lbcIngOnlyFalse := &LoadBalancerController{
		ingressClass:        ingressClass,
		useIngressClassOnly: false,
		metricsCollector:    collectors.NewControllerFakeCollector(),
	}
	var testsWithoutIngressClassOnlyVS = []struct {
		lbc      *LoadBalancerController
		ing      *conf_v1.VirtualServer
		expected bool
	}{
		{
			lbcIngOnlyFalse,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: "",
				},
			},
			true,
		},
		{
			lbcIngOnlyFalse,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: "gce",
				},
			},
			false,
		},
		{
			lbcIngOnlyFalse,
			&conf_v1.VirtualServer{
				Spec: conf_v1.VirtualServerSpec{
					IngressClass: ingressClass,
				},
			},
			true,
		},
		{
			lbcIngOnlyFalse,
			&conf_v1.VirtualServer{},
			true,
		},
	}

	for _, test := range testsWithIngressClassOnlyVS {
		if result := test.lbc.HasCorrectIngressClass(test.ing); result != test.expected {
			t.Errorf("lbc.HasCorrectIngressClass(ing), lbc.ingressClass=%v, lbc.useIngressClassOnly=%v, ingressClassKey=%v, ing.IngressClass=%v; got %v, expected %v",
				test.lbc.ingressClass, test.lbc.useIngressClassOnly, ingressClassKey, test.ing.Spec.IngressClass, result, test.expected)
		}
	}

	for _, test := range testsWithoutIngressClassOnlyVS {
		if result := test.lbc.HasCorrectIngressClass(test.ing); result != test.expected {
			t.Errorf("lbc.HasCorrectIngressClass(ing), lbc.ingressClass=%v, lbc.useIngressClassOnly=%v, ingressClassKey=%v, ing.IngressClass=%v; got %v, expected %v",
				test.lbc.ingressClass, test.lbc.useIngressClassOnly, ingressClassKey, test.ing.Spec.IngressClass, result, test.expected)
		}
	}
}

func TestComparePorts(t *testing.T) {
	scenarios := []struct {
		sp       v1.ServicePort
		cp       v1.ContainerPort
		expected bool
	}{
		{
			// match TargetPort.strval and Protocol
			v1.ServicePort{
				TargetPort: intstr.FromString("name"),
				Protocol:   v1.ProtocolTCP,
			},
			v1.ContainerPort{
				Name:          "name",
				Protocol:      v1.ProtocolTCP,
				ContainerPort: 80,
			},
			true,
		},
		{
			// don't match Name and Protocol
			v1.ServicePort{
				Name:     "name",
				Protocol: v1.ProtocolTCP,
			},
			v1.ContainerPort{
				Name:          "name",
				Protocol:      v1.ProtocolTCP,
				ContainerPort: 80,
			},
			false,
		},
		{
			// TargetPort intval mismatch, don't match by TargetPort.Name
			v1.ServicePort{
				Name:       "name",
				TargetPort: intstr.FromInt(80),
			},
			v1.ContainerPort{
				Name:          "name",
				ContainerPort: 81,
			},
			false,
		},
		{
			// match by TargetPort intval
			v1.ServicePort{
				TargetPort: intstr.IntOrString{
					IntVal: 80,
				},
			},
			v1.ContainerPort{
				ContainerPort: 80,
			},
			true,
		},
		{
			// Fall back on ServicePort.Port if TargetPort is empty
			v1.ServicePort{
				Name: "name",
				Port: 80,
			},
			v1.ContainerPort{
				Name:          "name",
				ContainerPort: 80,
			},
			true,
		},
		{
			// TargetPort intval mismatch
			v1.ServicePort{
				TargetPort: intstr.FromInt(80),
			},
			v1.ContainerPort{
				ContainerPort: 81,
			},
			false,
		},
		{
			// don't match empty ports
			v1.ServicePort{},
			v1.ContainerPort{},
			false,
		},
	}

	for _, scen := range scenarios {
		if scen.expected != compareContainerPortAndServicePort(scen.cp, scen.sp) {
			t.Errorf("Expected: %v, ContainerPort: %v, ServicePort: %v", scen.expected, scen.cp, scen.sp)
		}
	}
}

func TestFindProbeForPods(t *testing.T) {
	pods := []*v1.Pod{
		{
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						ReadinessProbe: &v1.Probe{
							Handler: v1.Handler{
								HTTPGet: &v1.HTTPGetAction{
									Path: "/",
									Host: "asdf.com",
									Port: intstr.IntOrString{
										IntVal: 80,
									},
								},
							},
							PeriodSeconds: 42,
						},
						Ports: []v1.ContainerPort{
							{
								Name:          "name",
								ContainerPort: 80,
								Protocol:      v1.ProtocolTCP,
								HostIP:        "1.2.3.4",
							},
						},
					},
				},
			},
		},
	}
	svcPort := v1.ServicePort{
		TargetPort: intstr.FromInt(80),
	}
	probe := findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as int match failed: %+v", probe)
	}

	svcPort = v1.ServicePort{
		TargetPort: intstr.FromString("name"),
		Protocol:   v1.ProtocolTCP,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as string failed: %+v", probe)
	}

	svcPort = v1.ServicePort{
		TargetPort: intstr.FromInt(80),
		Protocol:   v1.ProtocolTCP,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.TargetPort as int failed: %+v", probe)
	}

	svcPort = v1.ServicePort{
		Port: 80,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe == nil || probe.PeriodSeconds != 42 {
		t.Errorf("ServicePort.Port should match if TargetPort is not set: %+v", probe)
	}

	svcPort = v1.ServicePort{
		TargetPort: intstr.FromString("wrong_name"),
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.TargetPort should not have matched string: %+v", probe)
	}

	svcPort = v1.ServicePort{
		TargetPort: intstr.FromInt(22),
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.TargetPort should not have matched int: %+v", probe)
	}

	svcPort = v1.ServicePort{
		Port: 22,
	}
	probe = findProbeForPods(pods, &svcPort)
	if probe != nil {
		t.Errorf("ServicePort.Port mismatch: %+v", probe)
	}

}

func TestGetServicePortForIngressPort(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	cnf := configs.NewConfigurator(&nginx.LocalManager{}, &configs.StaticConfigParams{}, &configs.ConfigParams{}, &configs.GlobalConfigParams{}, &version1.TemplateExecutor{}, &version2.TemplateExecutor{}, false, false, nil, false, nil, false)
	lbc := LoadBalancerController{
		client:           fakeClient,
		ingressClass:     "nginx",
		configurator:     cnf,
		metricsCollector: collectors.NewControllerFakeCollector(),
	}
	svc := v1.Service{
		TypeMeta: meta_v1.TypeMeta{},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "coffee-svc",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "foo",
					Port:       80,
					TargetPort: intstr.FromInt(22),
				},
			},
		},
		Status: v1.ServiceStatus{},
	}
	ingSvcPort := intstr.FromString("foo")
	svcPort := lbc.getServicePortForIngressPort(ingSvcPort, &svc)
	if svcPort == nil || svcPort.Port != 80 {
		t.Errorf("TargetPort string match failed: %+v", svcPort)
	}

	ingSvcPort = intstr.FromInt(80)
	svcPort = lbc.getServicePortForIngressPort(ingSvcPort, &svc)
	if svcPort == nil || svcPort.Port != 80 {
		t.Errorf("TargetPort int match failed: %+v", svcPort)
	}

	ingSvcPort = intstr.FromInt(22)
	svcPort = lbc.getServicePortForIngressPort(ingSvcPort, &svc)
	if svcPort != nil {
		t.Errorf("Mismatched ints should not return port: %+v", svcPort)
	}
	ingSvcPort = intstr.FromString("bar")
	svcPort = lbc.getServicePortForIngressPort(ingSvcPort, &svc)
	if svcPort != nil {
		t.Errorf("Mismatched strings should not return port: %+v", svcPort)
	}
}

func TestFindTransportServersForService(t *testing.T) {
	ts1 := conf_v1alpha1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ts-1",
			Namespace: "ns-1",
		},
		Spec: conf_v1alpha1.TransportServerSpec{
			Upstreams: []conf_v1alpha1.Upstream{
				{
					Service: "test-service",
				},
			},
		},
	}
	ts2 := conf_v1alpha1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ts-2",
			Namespace: "ns-1",
		},
		Spec: conf_v1alpha1.TransportServerSpec{
			Upstreams: []conf_v1alpha1.Upstream{
				{
					Service: "some-service",
				},
			},
		},
	}
	ts3 := conf_v1alpha1.TransportServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ts-3",
			Namespace: "ns-2",
		},
		Spec: conf_v1alpha1.TransportServerSpec{
			Upstreams: []conf_v1alpha1.Upstream{
				{
					Service: "test-service",
				},
			},
		},
	}
	transportServers := []*conf_v1alpha1.TransportServer{&ts1, &ts2, &ts3}

	service := v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "test-service",
			Namespace: "ns-1",
		},
	}

	expected := []*conf_v1alpha1.TransportServer{&ts1}

	result := findTransportServersForService(transportServers, &service)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("findTransportServersForService returned %v but expected %v", result, expected)
	}
}

func TestFormatWarningsMessages(t *testing.T) {
	warnings := []string{"Test warning", "Test warning 2"}

	expected := "Test warning; Test warning 2"
	result := formatWarningMessages(warnings)

	if result != expected {
		t.Errorf("formatWarningMessages(%v) returned %v but expected %v", warnings, result, expected)
	}
}

func TestGetEndpointsBySubselectedPods(t *testing.T) {
	boolPointer := func(b bool) *bool { return &b }
	tests := []struct {
		desc        string
		targetPort  int32
		svcEps      v1.Endpoints
		expectedEps []podEndpoint
	}{
		{
			desc:       "find one endpoint",
			targetPort: 80,
			expectedEps: []podEndpoint{
				{
					Address: "1.2.3.4:80",
					MeshPodOwner: configs.MeshPodOwner{
						OwnerType: "deployment",
						OwnerName: "deploy-1",
					},
				},
			},
		},
		{
			desc:        "targetPort mismatch",
			targetPort:  21,
			expectedEps: nil,
		},
	}

	pods := []*v1.Pod{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				OwnerReferences: []meta_v1.OwnerReference{
					{
						Kind:       "Deployment",
						Name:       "deploy-1",
						Controller: boolPointer(true),
					},
				},
			},
			Status: v1.PodStatus{
				PodIP: "1.2.3.4",
			},
		},
	}

	svcEps := v1.Endpoints{
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP:       "1.2.3.4",
						Hostname: "asdf.com",
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port: 80,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotEndps := getEndpointsBySubselectedPods(test.targetPort, pods, svcEps)
			if !reflect.DeepEqual(gotEndps, test.expectedEps) {
				t.Errorf("getEndpointsBySubselectedPods() = %v, want %v", gotEndps, test.expectedEps)
			}
		})
	}
}

func TestGetStatusFromEventTitle(t *testing.T) {
	tests := []struct {
		eventTitle string
		expected   string
	}{
		{
			eventTitle: "",
			expected:   "",
		},
		{
			eventTitle: "AddedOrUpdatedWithError",
			expected:   "Invalid",
		},
		{
			eventTitle: "Rejected",
			expected:   "Invalid",
		},
		{
			eventTitle: "NoVirtualServersFound",
			expected:   "Invalid",
		},
		{
			eventTitle: "Missing Secret",
			expected:   "Invalid",
		},
		{
			eventTitle: "UpdatedWithError",
			expected:   "Invalid",
		},
		{
			eventTitle: "AddedOrUpdatedWithWarning",
			expected:   "Warning",
		},
		{
			eventTitle: "UpdatedWithWarning",
			expected:   "Warning",
		},
		{
			eventTitle: "AddedOrUpdated",
			expected:   "Valid",
		},
		{
			eventTitle: "Updated",
			expected:   "Valid",
		},
		{
			eventTitle: "New State",
			expected:   "",
		},
	}

	for _, test := range tests {
		result := getStatusFromEventTitle(test.eventTitle)
		if result != test.expected {
			t.Errorf("getStatusFromEventTitle(%v) returned %v but expected %v", test.eventTitle, result, test.expected)
		}
	}
}

func TestGetPolicies(t *testing.T) {
	validPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "valid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			AccessControl: &conf_v1.AccessControl{
				Allow: []string{"127.0.0.1"},
			},
		},
	}

	invalidPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{},
	}

	lbc := LoadBalancerController{
		isNginxPlus: true,
		policyLister: &cache.FakeCustomStore{
			GetByKeyFunc: func(key string) (item interface{}, exists bool, err error) {
				switch key {
				case "default/valid-policy":
					return validPolicy, true, nil
				case "default/invalid-policy":
					return invalidPolicy, true, nil
				case "nginx-ingress/valid-policy":
					return nil, false, nil
				default:
					return nil, false, errors.New("GetByKey error")
				}
			},
		},
	}

	policyRefs := []conf_v1.PolicyReference{
		{
			Name: "valid-policy",
			// Namespace is implicit here
		},
		{
			Name:      "invalid-policy",
			Namespace: "default",
		},
		{
			Name:      "valid-policy", // doesn't exist
			Namespace: "nginx-ingress",
		},
		{
			Name:      "some-policy", // will make lister return error
			Namespace: "nginx-ingress",
		},
	}

	expectedPolicies := []*conf_v1.Policy{validPolicy}
	expectedErrors := []error{
		errors.New("Policy default/invalid-policy is invalid: spec: Invalid value: \"\": must specify exactly one of: `accessControl`, `rateLimit`, `ingressMTLS`, `egressMTLS`, `jwt`"),
		errors.New("Policy nginx-ingress/valid-policy doesn't exist"),
		errors.New("Failed to get policy nginx-ingress/some-policy: GetByKey error"),
	}

	result, errors := lbc.getPolicies(policyRefs, "default")
	if !reflect.DeepEqual(result, expectedPolicies) {
		t.Errorf("lbc.getPolicies() returned \n%v but \nexpected %v", result, expectedPolicies)
	}
	if !reflect.DeepEqual(errors, expectedErrors) {
		t.Errorf("lbc.getPolicies() returned \n%v but expected \n%v", errors, expectedErrors)
	}
}

func TestCreatePolicyMap(t *testing.T) {
	policies := []*conf_v1.Policy{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-2",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "nginx-ingress",
			},
		},
	}

	expected := map[string]*conf_v1.Policy{
		"default/policy-1": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "default",
			},
		},
		"default/policy-2": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-2",
				Namespace: "default",
			},
		},
		"nginx-ingress/policy-1": {
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "policy-1",
				Namespace: "nginx-ingress",
			},
		},
	}

	result := createPolicyMap(policies)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("createPolicyMap() returned \n%s but expected \n%s", policyMapToString(result), policyMapToString(expected))
	}
}

func TestGetPodOwnerTypeAndName(t *testing.T) {
	tests := []struct {
		desc    string
		expType string
		expName string
		pod     *v1.Pod
	}{
		{
			desc:    "deployment",
			expType: "deployment",
			expName: "deploy-name",
			pod:     &v1.Pod{ObjectMeta: createTestObjMeta("Deployment", "deploy-name", true)},
		},
		{
			desc:    "stateful set",
			expType: "statefulset",
			expName: "statefulset-name",
			pod:     &v1.Pod{ObjectMeta: createTestObjMeta("StatefulSet", "statefulset-name", true)},
		},
		{
			desc:    "daemon set",
			expType: "daemonset",
			expName: "daemonset-name",
			pod:     &v1.Pod{ObjectMeta: createTestObjMeta("DaemonSet", "daemonset-name", true)},
		},
		{
			desc:    "replica set with no pod hash",
			expType: "deployment",
			expName: "replicaset-name",
			pod:     &v1.Pod{ObjectMeta: createTestObjMeta("ReplicaSet", "replicaset-name", false)},
		},
		{
			desc:    "replica set with pod hash",
			expType: "deployment",
			expName: "replicaset-name",
			pod: &v1.Pod{
				ObjectMeta: createTestObjMeta("ReplicaSet", "replicaset-name-67c6f7c5fd", true),
			},
		},
		{
			desc:    "nil controller should use default values",
			expType: "deployment",
			expName: "deploy-name",
			pod: &v1.Pod{
				ObjectMeta: meta_v1.ObjectMeta{
					OwnerReferences: []meta_v1.OwnerReference{
						{
							Name:       "deploy-name",
							Controller: nil,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			actualType, actualName := getPodOwnerTypeAndName(test.pod)
			if actualType != test.expType {
				t.Errorf("getPodOwnerTypeAndName() returned %s for owner type but expected %s", actualType, test.expType)
			}
			if actualName != test.expName {
				t.Errorf("getPodOwnerTypeAndName() returned %s for owner name but expected %s", actualName, test.expName)
			}
		})
	}
}

func createTestObjMeta(kind, name string, podHashLabel bool) meta_v1.ObjectMeta {
	controller := true
	meta := meta_v1.ObjectMeta{
		OwnerReferences: []meta_v1.OwnerReference{
			{
				Kind:       kind,
				Name:       name,
				Controller: &controller,
			},
		},
	}
	if podHashLabel {
		meta.Labels = map[string]string{
			"pod-template-hash": "67c6f7c5fd",
		}
	}
	return meta
}

func policyMapToString(policies map[string]*conf_v1.Policy) string {
	var keys []string
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder

	b.WriteString("[ ")
	for _, k := range keys {
		fmt.Fprintf(&b, "%q: '%s/%s', ", k, policies[k].Namespace, policies[k].Name)
	}
	b.WriteString("]")

	return b.String()
}

type testResource struct {
	keyWithKind string
}

func (*testResource) GetObjectMeta() *meta_v1.ObjectMeta {
	return nil
}

func (t *testResource) GetKeyWithKind() string {
	return t.keyWithKind
}

func (*testResource) AcquireHost(string) {
}

func (*testResource) ReleaseHost(string) {
}

func (*testResource) Wins(Resource) bool {
	return false
}

func (*testResource) IsSame(Resource) bool {
	return false
}

func (*testResource) AddWarning(string) {
}

func (*testResource) IsEqual(Resource) bool {
	return false
}

func (t *testResource) String() string {
	return t.keyWithKind
}

func TestRemoveDuplicateResources(t *testing.T) {
	tests := []struct {
		resources []Resource
		expected  []Resource
	}{
		{
			resources: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-1"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
			expected: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-1"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-2"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
		},
		{
			resources: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-2/vs-3"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
			expected: []Resource{
				&testResource{keyWithKind: "VirtualServer/ns-2/vs-3"},
				&testResource{keyWithKind: "VirtualServer/ns-1/vs-3"},
			},
		},
	}

	for _, test := range tests {
		result := removeDuplicateResources(test.resources)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("removeDuplicateResources() returned \n%v but expected \n%v", result, test.expected)
		}
	}
}

func TestFindPoliciesForSecret(t *testing.T) {
	jwtPol1 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			JWTAuth: &conf_v1.JWTAuth{
				Secret: "jwk-secret",
			},
		},
	}

	jwtPol2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "ns-1",
		},
		Spec: conf_v1.PolicySpec{
			JWTAuth: &conf_v1.JWTAuth{
				Secret: "jwk-secret",
			},
		},
	}

	ingTLSPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ingress-mtls-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			IngressMTLS: &conf_v1.IngressMTLS{
				ClientCertSecret: "ingress-mtls-secret",
			},
		},
	}
	egTLSPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "egress-mtls-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{
				TLSSecret: "egress-mtls-secret",
			},
		},
	}
	egTLSPol2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "egress-trusted-policy",
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			EgressMTLS: &conf_v1.EgressMTLS{
				TrustedCertSecret: "egress-trusted-secret",
			},
		},
	}

	tests := []struct {
		policies        []*conf_v1.Policy
		secretNamespace string
		secretName      string
		expected        []*conf_v1.Policy
		msg             string
	}{
		{
			policies:        []*conf_v1.Policy{jwtPol1},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        []*conf_v1.Policy{jwtPol1},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol2},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        nil,
			msg:             "Ignore policies in other namespaces",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, jwtPol2},
			secretNamespace: "default",
			secretName:      "jwk-secret",
			expected:        []*conf_v1.Policy{jwtPol1},
			msg:             "Find policy in default ns, ignore other",
		},
		{
			policies:        []*conf_v1.Policy{ingTLSPol},
			secretNamespace: "default",
			secretName:      "ingress-mtls-secret",
			expected:        []*conf_v1.Policy{ingTLSPol},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, ingTLSPol},
			secretNamespace: "default",
			secretName:      "ingress-mtls-secret",
			expected:        []*conf_v1.Policy{ingTLSPol},
			msg:             "Find policy in default ns, ignore other types",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol},
			secretNamespace: "default",
			secretName:      "egress-mtls-secret",
			expected:        []*conf_v1.Policy{egTLSPol},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{jwtPol1, egTLSPol},
			secretNamespace: "default",
			secretName:      "egress-mtls-secret",
			expected:        []*conf_v1.Policy{egTLSPol},
			msg:             "Find policy in default ns, ignore other types",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol2},
			secretNamespace: "default",
			secretName:      "egress-trusted-secret",
			expected:        []*conf_v1.Policy{egTLSPol2},
			msg:             "Find policy in default ns",
		},
		{
			policies:        []*conf_v1.Policy{egTLSPol, egTLSPol2},
			secretNamespace: "default",
			secretName:      "egress-trusted-secret",
			expected:        []*conf_v1.Policy{egTLSPol2},
			msg:             "Find policy in default ns, ignore other types",
		},
	}
	for _, test := range tests {
		result := findPoliciesForSecret(test.policies, test.secretNamespace, test.secretName)
		if diff := cmp.Diff(test.expected, result); diff != "" {
			t.Errorf("findPoliciesForSecret() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func errorComparer(e1, e2 error) bool {
	if e1 == nil || e2 == nil {
		return e1 == e2
	}

	return e1.Error() == e2.Error()
}

func TestAddJWTSecrets(t *testing.T) {
	invalidErr := errors.New("invalid")

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[string]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Secret: "valid-jwk-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-jwk-secret": {
					Type: secrets.SecretTypeJWK,
					Path: "/etc/nginx/secrets/default-valid-jwk-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting invalid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "jwt-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						JWTAuth: &conf_v1.JWTAuth{
							Secret: "invalid-jwk-secret",
							Realm:  "My API",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-jwk-secret": {
					Type:  secrets.SecretTypeJWK,
					Error: invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.StoredSecret{
			"default/valid-jwk-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "valid-jwk-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeJWK,
				},
				Path: "/etc/nginx/secrets/default-valid-jwk-secret",
			},
			"default/invalid-jwk-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "invalid-jwk-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeJWK,
				},
				ValidationErr: invalidErr,
			},
		}),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

		err := lbc.addJWTSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addJWTSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addJWTSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddIngressMTLSSecret(t *testing.T) {
	invalidErr := errors.New("invalid")

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[string]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "valid-ingress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-ingress-mtls-secret": {
					Type: secrets.SecretTypeCA,
					Path: "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secret",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						IngressMTLS: &conf_v1.IngressMTLS{
							ClientCertSecret: "invalid-ingress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-ingress-mtls-secret": {
					Type:  secrets.SecretTypeCA,
					Error: invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.StoredSecret{
			"default/valid-ingress-mtls-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "valid-ingress-mtls-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeCA,
				},
				Path: "/etc/nginx/secrets/default-valid-ingress-mtls-secret",
			},
			"default/invalid-ingress-mtls-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "invalid-ingress-mtls-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeCA,
				},
				ValidationErr: invalidErr,
			},
		}),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

		err := lbc.addIngressMTLSSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addIngressMTLSSecretRefs() returned %v, for the case of %v", err, test.msg)
		}

		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addIngressMTLSSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddEgressMTLSSecrets(t *testing.T) {
	invalidErr := errors.New("invalid")

	tests := []struct {
		policies           []*conf_v1.Policy
		expectedSecretRefs map[string]*secrets.SecretReference
		wantErr            bool
		msg                string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "valid-egress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-mtls-secret": {
					Type: api_v1.SecretTypeTLS,
					Path: "/etc/nginx/secrets/default-valid-egress-mtls-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid TLS secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-egress-trusted-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "valid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-trusted-secret": {
					Type: secrets.SecretTypeCA,
					Path: "/etc/nginx/secrets/default-valid-egress-trusted-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid TrustedCA secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret:         "valid-egress-mtls-secret",
							TrustedCertSecret: "valid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/valid-egress-mtls-secret": {
					Type: api_v1.SecretTypeTLS,
					Path: "/etc/nginx/secrets/default-valid-egress-mtls-secret",
				},
				"default/valid-egress-trusted-secret": {
					Type: secrets.SecretTypeCA,
					Path: "/etc/nginx/secrets/default-valid-egress-trusted-secret",
				},
			},
			wantErr: false,
			msg:     "test getting valid secrets",
		},
		{
			policies:           []*conf_v1.Policy{},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with no policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "ingress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						AccessControl: &conf_v1.AccessControl{
							Allow: []string{"127.0.0.1"},
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{},
			wantErr:            false,
			msg:                "test getting valid secret with wrong policy",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TLSSecret: "invalid-egress-mtls-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-egress-mtls-secret": {
					Type:  api_v1.SecretTypeTLS,
					Error: invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid TLS secret",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "egress-mtls-policy",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						EgressMTLS: &conf_v1.EgressMTLS{
							TrustedCertSecret: "invalid-egress-trusted-secret",
						},
					},
				},
			},
			expectedSecretRefs: map[string]*secrets.SecretReference{
				"default/invalid-egress-trusted-secret": {
					Type:  secrets.SecretTypeCA,
					Error: invalidErr,
				},
			},
			wantErr: true,
			msg:     "test getting invalid TrustedCA secret",
		},
	}

	lbc := LoadBalancerController{
		secretStore: secrets.NewFakeSecretsStore(map[string]*secrets.StoredSecret{
			"default/valid-egress-mtls-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "valid-egress-mtls-secret",
						Namespace: "default",
					},
					Type: api_v1.SecretTypeTLS,
				},
				Path: "/etc/nginx/secrets/default-valid-egress-mtls-secret",
			},
			"default/valid-egress-trusted-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "valid-egress-trusted-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeCA,
				},
				Path: "/etc/nginx/secrets/default-valid-egress-trusted-secret",
			},
			"default/invalid-egress-mtls-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "invalid-egress-mtls-secret",
						Namespace: "default",
					},
					Type: api_v1.SecretTypeTLS,
				},
				ValidationErr: invalidErr,
			},
			"default/invalid-egress-trusted-secret": {
				Secret: &v1.Secret{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "invalid-egress-trusted-secret",
						Namespace: "default",
					},
					Type: secrets.SecretTypeCA,
				},
				ValidationErr: invalidErr,
			},
		}),
	}

	for _, test := range tests {
		result := make(map[string]*secrets.SecretReference)

		err := lbc.addEgressMTLSSecretRefs(result, test.policies)
		if (err != nil) != test.wantErr {
			t.Errorf("addEgressMTLSSecretRefs() returned %v, for the case of %v", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedSecretRefs, result, cmp.Comparer(errorComparer)); diff != "" {
			t.Errorf("addEgressMTLSSecretRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}
