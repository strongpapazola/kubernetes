/*
Copyright 2015 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/secrets"
	"github.com/spiffe/go-spiffe/workload"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	core_v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/record"

	"github.com/nginxinc/kubernetes-ingress/internal/configs"
	"github.com/nginxinc/kubernetes-ingress/internal/metrics/collectors"

	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	conf_v1alpha1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1alpha1"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/validation"
	k8s_nginx "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

const (
	ingressClassKey = "kubernetes.io/ingress.class"
	// IngressControllerName holds Ingress Controller name
	IngressControllerName = "nginx.org/ingress-controller"
)

var (
	appProtectPolicyGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "appolicies",
	}
	appProtectPolicyGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APPolicy",
	}
	appProtectLogConfGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "aplogconfs",
	}
	appProtectLogConfGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APLogConf",
	}
	nginxCisConnectorGVR = schema.GroupVersionResource{
		Group:    "cis.f5.com",
		Version:  "v1",
		Resource: "nginxcisconnectors",
	}
	appProtectUserSigGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "apusersigs",
	}
	appProtectUserSigGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APUserSig",
	}
	nginxCisConnectorGVK = schema.GroupVersionKind{
		Group:   "cis.f5.com",
		Version: "v1",
		Kind:    "NginxCisConnector",
	}
)

type podEndpoint struct {
	Address string
	PodName string
	// MeshPodOwner is used for NGINX Service Mesh metrics
	configs.MeshPodOwner
}

// LoadBalancerController watches Kubernetes API and
// reconfigures NGINX via NginxController when needed
type LoadBalancerController struct {
	client                        kubernetes.Interface
	confClient                    k8s_nginx.Interface
	dynClient                     dynamic.Interface
	ingressController             cache.Controller
	svcController                 cache.Controller
	endpointController            cache.Controller
	configMapController           cache.Controller
	secretController              cache.Controller
	virtualServerController       cache.Controller
	virtualServerRouteController  cache.Controller
	podController                 cache.Controller
	dynInformerFactory            dynamicinformer.DynamicSharedInformerFactory
	appProtectPolicyInformer      cache.SharedIndexInformer
	appProtectLogConfInformer     cache.SharedIndexInformer
	appProtectUserSigInformer     cache.SharedIndexInformer
	globalConfigurationController cache.Controller
	transportServerController     cache.Controller
	policyController              cache.Controller
	nginxCisConnectorInformer     cache.SharedIndexInformer
	ingressLister                 storeToIngressLister
	svcLister                     cache.Store
	endpointLister                storeToEndpointLister
	configMapLister               storeToConfigMapLister
	podLister                     indexerToPodLister
	secretLister                  storeToSecretLister
	virtualServerLister           cache.Store
	virtualServerRouteLister      cache.Store
	appProtectPolicyLister        cache.Store
	appProtectLogConfLister       cache.Store
	globalConfigurationLister     cache.Store
	appProtectUserSigLister       cache.Store
	transportServerLister         cache.Store
	policyLister                  cache.Store
	nginxCisConnectorLister       cache.Store
	syncQueue                     *taskQueue
	ctx                           context.Context
	cancel                        context.CancelFunc
	configurator                  *configs.Configurator
	watchNginxConfigMaps          bool
	watchGlobalConfiguration      bool
	watchNginxCisConnector        bool
	isNginxPlus                   bool
	appProtectEnabled             bool
	recorder                      record.EventRecorder
	defaultServerSecret           string
	ingressClass                  string
	useIngressClassOnly           bool
	statusUpdater                 *statusUpdater
	leaderElector                 *leaderelection.LeaderElector
	reportIngressStatus           bool
	isLeaderElectionEnabled       bool
	leaderElectionLockName        string
	resync                        time.Duration
	namespace                     string
	controllerNamespace           string
	wildcardTLSSecret             string
	areCustomResourcesEnabled     bool
	enablePreviewPolicies         bool
	metricsCollector              collectors.ControllerCollector
	globalConfigurationValidator  *validation.GlobalConfigurationValidator
	transportServerValidator      *validation.TransportServerValidator
	spiffeController              *spiffeController
	internalRoutesEnabled         bool
	syncLock                      sync.Mutex
	isNginxReady                  bool
	isPrometheusEnabled           bool
	isLatencyMetricsEnabled       bool
	configuration                 *Configuration
	secretStore                   secrets.SecretStore
	appProtectConfiguration       *AppProtectConfiguration
}

var keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

// NewLoadBalancerControllerInput holds the input needed to call NewLoadBalancerController.
type NewLoadBalancerControllerInput struct {
	KubeClient                   kubernetes.Interface
	ConfClient                   k8s_nginx.Interface
	DynClient                    dynamic.Interface
	ResyncPeriod                 time.Duration
	Namespace                    string
	NginxConfigurator            *configs.Configurator
	DefaultServerSecret          string
	AppProtectEnabled            bool
	IsNginxPlus                  bool
	IngressClass                 string
	UseIngressClassOnly          bool
	ExternalServiceName          string
	NginxCisConnector            string
	ControllerNamespace          string
	ReportIngressStatus          bool
	IsLeaderElectionEnabled      bool
	LeaderElectionLockName       string
	WildcardTLSSecret            string
	ConfigMaps                   string
	GlobalConfiguration          string
	AreCustomResourcesEnabled    bool
	EnablePreviewPolicies        bool
	MetricsCollector             collectors.ControllerCollector
	GlobalConfigurationValidator *validation.GlobalConfigurationValidator
	TransportServerValidator     *validation.TransportServerValidator
	VirtualServerValidator       *validation.VirtualServerValidator
	SpireAgentAddress            string
	InternalRoutesEnabled        bool
	IsPrometheusEnabled          bool
	IsLatencyMetricsEnabled      bool
}

// NewLoadBalancerController creates a controller
func NewLoadBalancerController(input NewLoadBalancerControllerInput) *LoadBalancerController {
	lbc := &LoadBalancerController{
		client:                       input.KubeClient,
		confClient:                   input.ConfClient,
		dynClient:                    input.DynClient,
		configurator:                 input.NginxConfigurator,
		defaultServerSecret:          input.DefaultServerSecret,
		appProtectEnabled:            input.AppProtectEnabled,
		isNginxPlus:                  input.IsNginxPlus,
		ingressClass:                 input.IngressClass,
		useIngressClassOnly:          input.UseIngressClassOnly,
		reportIngressStatus:          input.ReportIngressStatus,
		isLeaderElectionEnabled:      input.IsLeaderElectionEnabled,
		leaderElectionLockName:       input.LeaderElectionLockName,
		resync:                       input.ResyncPeriod,
		namespace:                    input.Namespace,
		controllerNamespace:          input.ControllerNamespace,
		wildcardTLSSecret:            input.WildcardTLSSecret,
		areCustomResourcesEnabled:    input.AreCustomResourcesEnabled,
		enablePreviewPolicies:        input.EnablePreviewPolicies,
		metricsCollector:             input.MetricsCollector,
		globalConfigurationValidator: input.GlobalConfigurationValidator,
		transportServerValidator:     input.TransportServerValidator,
		internalRoutesEnabled:        input.InternalRoutesEnabled,
		isPrometheusEnabled:          input.IsPrometheusEnabled,
		isLatencyMetricsEnabled:      input.IsLatencyMetricsEnabled,
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&core_v1.EventSinkImpl{
		Interface: core_v1.New(input.KubeClient.CoreV1().RESTClient()).Events(""),
	})
	lbc.recorder = eventBroadcaster.NewRecorder(scheme.Scheme,
		api_v1.EventSource{Component: "nginx-ingress-controller"})

	lbc.syncQueue = newTaskQueue(lbc.sync)
	if input.SpireAgentAddress != "" {
		var err error
		lbc.spiffeController, err = NewSpiffeController(lbc.syncSVIDRotation, input.SpireAgentAddress)
		if err != nil {
			glog.Fatalf("failed to create Spiffe Controller: %v", err)
		}
	}

	glog.V(3).Infof("Nginx Ingress Controller has class: %v", input.IngressClass)

	// create handlers for resources we care about
	lbc.addSecretHandler(createSecretHandlers(lbc))
	lbc.addIngressHandler(createIngressHandlers(lbc))
	lbc.addServiceHandler(createServiceHandlers(lbc))
	lbc.addEndpointHandler(createEndpointHandlers(lbc))
	lbc.addPodHandler()
	if lbc.appProtectEnabled {
		lbc.dynInformerFactory = dynamicinformer.NewDynamicSharedInformerFactory(lbc.dynClient, 0)
		lbc.addAppProtectPolicyHandler(createAppProtectPolicyHandlers(lbc))
		lbc.addAppProtectLogConfHandler(createAppProtectLogConfHandlers(lbc))
		lbc.addAppProtectUserSigHandler(createAppProtectUserSigHandlers(lbc))
	}

	if lbc.areCustomResourcesEnabled {
		lbc.addVirtualServerHandler(createVirtualServerHandlers(lbc))
		lbc.addVirtualServerRouteHandler(createVirtualServerRouteHandlers(lbc))
		lbc.addTransportServerHandler(createTransportServerHandlers(lbc))
		lbc.addPolicyHandler(createPolicyHandlers(lbc))

		if input.GlobalConfiguration != "" {
			lbc.watchGlobalConfiguration = true

			ns, name, _ := ParseNamespaceName(input.GlobalConfiguration)

			lbc.addGlobalConfigurationHandler(createGlobalConfigurationHandlers(lbc), ns, name)
		}
	}

	if input.ConfigMaps != "" {
		nginxConfigMapsNS, nginxConfigMapsName, err := ParseNamespaceName(input.ConfigMaps)
		if err != nil {
			glog.Warning(err)
		} else {
			lbc.watchNginxConfigMaps = true
			lbc.addConfigMapHandler(createConfigMapHandlers(lbc, nginxConfigMapsName), nginxConfigMapsNS)
		}
	}

	if input.NginxCisConnector != "" {
		lbc.watchNginxCisConnector = true
		lbc.addNginxCisConnectorHandler(createNginxCisConnectorHandlers(lbc), input.NginxCisConnector)
	}

	if input.IsLeaderElectionEnabled {
		lbc.addLeaderHandler(createLeaderHandler(lbc))
	}

	lbc.statusUpdater = &statusUpdater{
		client:                   input.KubeClient,
		namespace:                input.ControllerNamespace,
		externalServiceName:      input.ExternalServiceName,
		ingressLister:            &lbc.ingressLister,
		virtualServerLister:      lbc.virtualServerLister,
		virtualServerRouteLister: lbc.virtualServerRouteLister,
		keyFunc:                  keyFunc,
		confClient:               input.ConfClient,
	}

	lbc.configuration = NewConfiguration(
		lbc.HasCorrectIngressClass,
		input.IsNginxPlus,
		input.AppProtectEnabled,
		input.InternalRoutesEnabled,
		input.VirtualServerValidator)

	lbc.appProtectConfiguration = NewAppProtectConfiguration()

	lbc.secretStore = secrets.NewLocalSecretStore(lbc.configurator)

	lbc.updateIngressMetrics()
	return lbc
}

// addLeaderHandler adds the handler for leader election to the controller
func (lbc *LoadBalancerController) addLeaderHandler(leaderHandler leaderelection.LeaderCallbacks) {
	var err error
	lbc.leaderElector, err = newLeaderElector(lbc.client, leaderHandler, lbc.controllerNamespace, lbc.leaderElectionLockName)
	if err != nil {
		glog.V(3).Infof("Error starting LeaderElection: %v", err)
	}
}

// AddSyncQueue enqueues the provided item on the sync queue
func (lbc *LoadBalancerController) AddSyncQueue(item interface{}) {
	lbc.syncQueue.Enqueue(item)
}

// addappProtectPolicyHandler creates dynamic informers for custom appprotect policy resource
func (lbc *LoadBalancerController) addAppProtectPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.appProtectPolicyInformer = lbc.dynInformerFactory.ForResource(appProtectPolicyGVR).Informer()
	lbc.appProtectPolicyLister = lbc.appProtectPolicyInformer.GetStore()
	lbc.appProtectPolicyInformer.AddEventHandler(handlers)
}

// addappProtectLogConfHandler creates dynamic informer for custom appprotect logging config resource
func (lbc *LoadBalancerController) addAppProtectLogConfHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.appProtectLogConfInformer = lbc.dynInformerFactory.ForResource(appProtectLogConfGVR).Informer()
	lbc.appProtectLogConfLister = lbc.appProtectLogConfInformer.GetStore()
	lbc.appProtectLogConfInformer.AddEventHandler(handlers)
}

// addappProtectUserSigHandler creates dynamic informer for custom appprotect user defined signature resource
func (lbc *LoadBalancerController) addAppProtectUserSigHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.appProtectUserSigInformer = lbc.dynInformerFactory.ForResource(appProtectUserSigGVR).Informer()
	lbc.appProtectUserSigLister = lbc.appProtectUserSigInformer.GetStore()
	lbc.appProtectUserSigInformer.AddEventHandler(handlers)
}

// addSecretHandler adds the handler for secrets to the controller
func (lbc *LoadBalancerController) addSecretHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.secretLister.Store, lbc.secretController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"secrets",
			lbc.namespace,
			fields.Everything()),
		&api_v1.Secret{},
		lbc.resync,
		handlers,
	)
}

// addServiceHandler adds the handler for services to the controller
func (lbc *LoadBalancerController) addServiceHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.svcLister, lbc.svcController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"services",
			lbc.namespace,
			fields.Everything()),
		&api_v1.Service{},
		lbc.resync,
		handlers,
	)
}

// addIngressHandler adds the handler for ingresses to the controller
func (lbc *LoadBalancerController) addIngressHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.ingressLister.Store, lbc.ingressController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.client.NetworkingV1beta1().RESTClient(),
			"ingresses",
			lbc.namespace,
			fields.Everything()),
		&networking.Ingress{},
		lbc.resync,
		handlers,
	)
}

// addEndpointHandler adds the handler for endpoints to the controller
func (lbc *LoadBalancerController) addEndpointHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.endpointLister.Store, lbc.endpointController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"endpoints",
			lbc.namespace,
			fields.Everything()),
		&api_v1.Endpoints{},
		lbc.resync,
		handlers,
	)
}

// addConfigMapHandler adds the handler for config maps to the controller
func (lbc *LoadBalancerController) addConfigMapHandler(handlers cache.ResourceEventHandlerFuncs, namespace string) {
	lbc.configMapLister.Store, lbc.configMapController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"configmaps",
			namespace,
			fields.Everything()),
		&api_v1.ConfigMap{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addPodHandler() {
	lbc.podLister.Indexer, lbc.podController = cache.NewIndexerInformer(
		cache.NewListWatchFromClient(
			lbc.client.CoreV1().RESTClient(),
			"pods",
			lbc.namespace,
			fields.Everything()),
		&api_v1.Pod{},
		lbc.resync,
		cache.ResourceEventHandlerFuncs{},
		cache.Indexers{},
	)
}

func (lbc *LoadBalancerController) addVirtualServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.virtualServerLister, lbc.virtualServerController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.confClient.K8sV1().RESTClient(),
			"virtualservers",
			lbc.namespace,
			fields.Everything()),
		&conf_v1.VirtualServer{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addVirtualServerRouteHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.virtualServerRouteLister, lbc.virtualServerRouteController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.confClient.K8sV1().RESTClient(),
			"virtualserverroutes",
			lbc.namespace,
			fields.Everything()),
		&conf_v1.VirtualServerRoute{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addPolicyHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.policyLister, lbc.policyController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.confClient.K8sV1().RESTClient(),
			"policies",
			lbc.namespace,
			fields.Everything()),
		&conf_v1.Policy{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addGlobalConfigurationHandler(handlers cache.ResourceEventHandlerFuncs, namespace string, name string) {
	lbc.globalConfigurationLister, lbc.globalConfigurationController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.confClient.K8sV1alpha1().RESTClient(),
			"globalconfigurations",
			namespace,
			fields.Set{"metadata.name": name}.AsSelector()),
		&conf_v1alpha1.GlobalConfiguration{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addTransportServerHandler(handlers cache.ResourceEventHandlerFuncs) {
	lbc.transportServerLister, lbc.transportServerController = cache.NewInformer(
		cache.NewListWatchFromClient(
			lbc.confClient.K8sV1alpha1().RESTClient(),
			"transportservers",
			lbc.namespace,
			fields.Everything()),
		&conf_v1alpha1.TransportServer{},
		lbc.resync,
		handlers,
	)
}

func (lbc *LoadBalancerController) addNginxCisConnectorHandler(handlers cache.ResourceEventHandlerFuncs, name string) {
	optionsModifier := func(options *meta_v1.ListOptions) {
		options.FieldSelector = fields.Set{"metadata.name": name}.String()
	}

	informer := dynamicinformer.NewFilteredDynamicInformer(lbc.dynClient, nginxCisConnectorGVR, lbc.controllerNamespace, lbc.resync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, optionsModifier)

	informer.Informer().AddEventHandlerWithResyncPeriod(handlers, lbc.resync)

	lbc.nginxCisConnectorInformer = informer.Informer()
	lbc.nginxCisConnectorLister = informer.Informer().GetStore()
}

// Run starts the loadbalancer controller
func (lbc *LoadBalancerController) Run() {
	lbc.ctx, lbc.cancel = context.WithCancel(context.Background())
	if lbc.appProtectEnabled {
		go lbc.dynInformerFactory.Start(lbc.ctx.Done())
	}

	if lbc.spiffeController != nil {
		err := lbc.spiffeController.Start(lbc.ctx.Done(), lbc.addInternalRouteServer)
		if err != nil {
			glog.Fatal(err)
		}
	}

	if lbc.leaderElector != nil {
		go lbc.leaderElector.Run(lbc.ctx)
	}
	go lbc.svcController.Run(lbc.ctx.Done())
	go lbc.podController.Run(lbc.ctx.Done())
	go lbc.endpointController.Run(lbc.ctx.Done())
	go lbc.secretController.Run(lbc.ctx.Done())
	if lbc.watchNginxConfigMaps {
		go lbc.configMapController.Run(lbc.ctx.Done())
	}
	go lbc.ingressController.Run(lbc.ctx.Done())

	if lbc.areCustomResourcesEnabled {
		go lbc.virtualServerController.Run(lbc.ctx.Done())
		go lbc.virtualServerRouteController.Run(lbc.ctx.Done())
		go lbc.transportServerController.Run(lbc.ctx.Done())
		go lbc.policyController.Run(lbc.ctx.Done())
	}
	if lbc.watchGlobalConfiguration {
		go lbc.globalConfigurationController.Run(lbc.ctx.Done())
	}
	if lbc.watchNginxCisConnector {
		go lbc.nginxCisConnectorInformer.Run(lbc.ctx.Done())
	}

	go lbc.syncQueue.Run(time.Second, lbc.ctx.Done())
	<-lbc.ctx.Done()
}

// Stop shutdowns the load balancer controller
func (lbc *LoadBalancerController) Stop() {
	lbc.cancel()

	lbc.syncQueue.Shutdown()
}

func (lbc *LoadBalancerController) syncEndpoints(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing endpoints %v", key)

	obj, endpExists, err := lbc.endpointLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !endpExists {
		return
	}

	endp := obj.(*api_v1.Endpoints)
	resources := lbc.configuration.FindResourcesForEndpoints(endp.Namespace, endp.Name)

	ingressExes, mergeableIngresses, virtualServersExes := lbc.createExtendedResources(resources)

	if len(ingressExes) > 0 {
		glog.V(3).Infof("Updating Endpoints for %v", ingressExes)
		err = lbc.configurator.UpdateEndpoints(ingressExes)
		if err != nil {
			glog.Errorf("Error updating endpoints for %v: %v", ingressExes, err)
		}
	}

	if len(mergeableIngresses) > 0 {
		glog.V(3).Infof("Updating Endpoints for %v", mergeableIngresses)
		err = lbc.configurator.UpdateEndpointsMergeableIngress(mergeableIngresses)
		if err != nil {
			glog.Errorf("Error updating endpoints for %v: %v", mergeableIngresses, err)
		}
	}

	if lbc.areCustomResourcesEnabled {
		if len(virtualServersExes) > 0 {
			glog.V(3).Infof("Updating endpoints for %v", virtualServersExes)
			err := lbc.configurator.UpdateEndpointsForVirtualServers(virtualServersExes)
			if err != nil {
				glog.Errorf("Error updating endpoints for %v: %v", virtualServersExes, err)
			}
		}

		transportServers := lbc.getTransportServersForEndpoints(obj.(*api_v1.Endpoints))
		transportServerExes := lbc.transportServersToTransportServerExes(transportServers)

		if len(transportServerExes) > 0 {
			glog.V(3).Infof("Updating endpoints for %v", transportServerExes)
			err := lbc.configurator.UpdateEndpointsForTransportServers(transportServerExes)
			if err != nil {
				glog.Errorf("Error updating endpoints for %v: %v", transportServerExes, err)
			}
		}
	}
}

func (lbc *LoadBalancerController) createExtendedResources(resources []Resource) ([]*configs.IngressEx, []*configs.MergeableIngresses, []*configs.VirtualServerEx) {
	var ingressExes []*configs.IngressEx
	var mergeableIngresses []*configs.MergeableIngresses
	var virtualServersExes []*configs.VirtualServerEx

	for _, r := range resources {
		switch impl := r.(type) {
		case *VirtualServerConfiguration:
			vs := impl.VirtualServer
			vsEx := lbc.createVirtualServerEx(vs, impl.VirtualServerRoutes)
			virtualServersExes = append(virtualServersExes, vsEx)
		case *IngressConfiguration:
			if impl.IsMaster {
				mergeableIng := lbc.createMergeableIngresses(impl)
				mergeableIngresses = append(mergeableIngresses, mergeableIng)
			} else {
				ingEx := lbc.createIngressEx(impl.Ingress, impl.ValidHosts, nil)
				ingressExes = append(ingressExes, ingEx)
			}
		}
	}

	return ingressExes, mergeableIngresses, virtualServersExes
}

func (lbc *LoadBalancerController) syncConfigMap(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing configmap %v", key)

	obj, configExists, err := lbc.configMapLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}
	cfgParams := configs.NewDefaultConfigParams()

	if configExists {
		cfgm := obj.(*api_v1.ConfigMap)
		cfgParams = configs.ParseConfigMap(cfgm, lbc.isNginxPlus, lbc.appProtectEnabled)

		lbc.statusUpdater.SaveStatusFromExternalStatus(cfgm.Data["external-status-address"])
	}

	resources := lbc.configuration.GetResources()

	glog.V(3).Infof("Updating %v resources", len(resources))

	ingressExes, mergeableIngresses, virtualServerExes := lbc.createExtendedResources(resources)

	warnings, updateErr := lbc.configurator.UpdateConfig(cfgParams, ingressExes, mergeableIngresses, virtualServerExes)

	eventTitle := "Updated"
	eventType := api_v1.EventTypeNormal
	eventWarningMessage := ""

	if updateErr != nil {
		eventTitle = "UpdatedWithError"
		eventType = api_v1.EventTypeWarning
		eventWarningMessage = fmt.Sprintf("but was not applied: %v", updateErr)
	}

	if len(warnings) > 0 && updateErr == nil {
		eventWarningMessage = "with warnings. Please check the logs"
	}

	if configExists {
		cfgm := obj.(*api_v1.ConfigMap)
		lbc.recorder.Eventf(cfgm, eventType, eventTitle, "Configuration from %v was updated %s", key, eventWarningMessage)
	}

	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
}

func (lbc *LoadBalancerController) transportServersToTransportServerExes(transportServers []*conf_v1alpha1.TransportServer) []*configs.TransportServerEx {
	var transportServerExes []*configs.TransportServerEx

	for _, ts := range transportServers {
		tsEx := lbc.createTransportServer(ts)
		transportServerExes = append(transportServerExes, tsEx)
	}

	return transportServerExes
}

func (lbc *LoadBalancerController) sync(task task) {
	glog.V(3).Infof("Syncing %v", task.Key)
	if lbc.spiffeController != nil {
		lbc.syncLock.Lock()
		defer lbc.syncLock.Unlock()
	}
	switch task.Kind {
	case ingress:
		lbc.syncIngress(task)
		lbc.updateIngressMetrics()
	case configMap:
		lbc.syncConfigMap(task)
	case endpoints:
		lbc.syncEndpoints(task)
	case secret:
		lbc.syncSecret(task)
	case service:
		lbc.syncService(task)
	case virtualserver:
		lbc.syncVirtualServer(task)
		lbc.updateVirtualServerMetrics()
	case virtualServerRoute:
		lbc.syncVirtualServerRoute(task)
		lbc.updateVirtualServerMetrics()
	case globalConfiguration:
		lbc.syncGlobalConfiguration(task)
	case transportserver:
		lbc.syncTransportServer(task)
	case policy:
		lbc.syncPolicy(task)
	case appProtectPolicy:
		lbc.syncAppProtectPolicy(task)
	case appProtectLogConf:
		lbc.syncAppProtectLogConf(task)
	case appProtectUserSig:
		lbc.syncAppProtectUserSig(task)
	case nginxCisConnector:
		lbc.syncNginxCisConnector(task)
	}

	if !lbc.isNginxReady && lbc.syncQueue.Len() == 0 {
		lbc.isNginxReady = true
		glog.V(3).Infof("NGINX is ready")
	}
}

func (lbc *LoadBalancerController) syncNginxCisConnector(task task) {
	key := task.Key
	glog.V(2).Infof("Adding, Updating or Deleting NginxCisConnector: %v", key)

	obj, exists, err := lbc.nginxCisConnectorLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !exists {
		// connector got removed
		lbc.statusUpdater.ClearStatusFromNginxCisConnector()
	} else {
		// connector is added or updated
		con := obj.(*unstructured.Unstructured)

		// spec.virtualServerAddress contains the IP of the BIG-IP device
		ip, found, err := unstructured.NestedString(con.Object, "spec", "virtualServerAddress")
		if err != nil {
			glog.Errorf("Failed to get virtualServerAddress from NginxCisConnector %s: %v", key, err)
			lbc.statusUpdater.ClearStatusFromNginxCisConnector()
		} else if !found {
			glog.Errorf("virtualServerAddress is not found in NginxCisConnector %s", key)
			lbc.statusUpdater.ClearStatusFromNginxCisConnector()
		} else if ip == "" {
			glog.Warningf("NginxCisConnector %s has the empty virtualServerAddress field", key)
			lbc.statusUpdater.ClearStatusFromNginxCisConnector()
		} else {
			lbc.statusUpdater.SaveStatusFromNginxCisConnector(ip)
		}
	}

	if lbc.reportStatusEnabled() {
		ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

		glog.V(3).Infof("Updating status for %v Ingresses", len(ingresses))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
		if err != nil {
			glog.Errorf("Error updating ingress status in syncNginxCisConnector: %v", err)
		}
	}

	if lbc.areCustomResourcesEnabled && lbc.reportVsVsrStatusEnabled() {
		virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

		glog.V(3).Infof("Updating status for %v VirtualServers", len(virtualServers))

		err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
		if err != nil {
			glog.V(3).Infof("Error updating VirtualServer/VirtualServerRoute status in syncNginxCisConnector: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) syncPolicy(task task) {
	key := task.Key
	obj, polExists, err := lbc.policyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	glog.V(2).Infof("Adding, Updating or Deleting Policy: %v\n", key)

	if polExists {
		pol := obj.(*conf_v1.Policy)
		err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enablePreviewPolicies)
		if err != nil {
			lbc.recorder.Eventf(pol, api_v1.EventTypeWarning, "Rejected", "Policy %v is invalid and was rejected: %v", key, err)
		} else {
			lbc.recorder.Eventf(pol, api_v1.EventTypeNormal, "AddedOrUpdated", "Policy %v was added or updated", key)
		}
	}

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForPolicy(namespace, name)
	// Ingresses don't have policies
	_, _, virtualServerExes := lbc.createExtendedResources(resources)

	if len(virtualServerExes) == 0 {
		return
	}

	warnings, updateErr := lbc.configurator.AddOrUpdateVirtualServers(virtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)

	// Note: updating the status of a policy based on a reload is not needed.
}

func (lbc *LoadBalancerController) syncTransportServer(task task) {
	key := task.Key
	obj, tsExists, err := lbc.transportServerLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !tsExists {
		glog.V(2).Infof("Deleting TransportServer: %v\n", key)

		err := lbc.configurator.DeleteTransportServer(key)
		if err != nil {
			glog.Errorf("Error when deleting configuration for %v: %v", key, err)
		}
		return
	}

	glog.V(2).Infof("Adding or Updating TransportServer: %v\n", key)

	ts := obj.(*conf_v1alpha1.TransportServer)

	validationErr := lbc.transportServerValidator.ValidateTransportServer(ts)
	if validationErr != nil {
		err := lbc.configurator.DeleteTransportServer(key)
		if err != nil {
			glog.Errorf("Error when deleting configuration for %v: %v", key, err)
		}
		lbc.recorder.Eventf(ts, api_v1.EventTypeWarning, "Rejected", "TransportServer %v is invalid and was rejected: %v", key, validationErr)
		return
	}

	if !lbc.configurator.CheckIfListenerExists(&ts.Spec.Listener) {
		err := lbc.configurator.DeleteTransportServer(key)
		if err != nil {
			glog.Errorf("Error when deleting configuration for %v: %v", key, err)
		}
		lbc.recorder.Eventf(ts, api_v1.EventTypeWarning, "Rejected", "TransportServer %v references a non-existing listener and was rejected", key)
		return
	}

	tsEx := lbc.createTransportServer(ts)

	addErr := lbc.configurator.AddOrUpdateTransportServer(tsEx)

	eventTitle := "AddedOrUpdated"
	eventType := api_v1.EventTypeNormal
	eventWarningMessage := ""

	if addErr != nil {
		eventTitle = "AddedOrUpdatedWithError"
		eventType = api_v1.EventTypeWarning
		eventWarningMessage = fmt.Sprintf("but was not applied: %v", addErr)
	}

	lbc.recorder.Eventf(ts, eventType, eventTitle, "Configuration for %v was added or updated %v", key, eventWarningMessage)
}

func (lbc *LoadBalancerController) syncGlobalConfiguration(task task) {
	key := task.Key
	obj, gcExists, err := lbc.globalConfigurationLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	if !gcExists {
		glog.Warningf("GlobalConfiguration %v was removed. Retaining the GlobalConfiguration,", key)
		return
	}

	glog.V(2).Infof("GlobalConfiguration was updated: %v\n", key)

	gc := obj.(*conf_v1alpha1.GlobalConfiguration)

	validationErr := lbc.globalConfigurationValidator.ValidateGlobalConfiguration(gc)
	if validationErr != nil {
		lbc.recorder.Eventf(gc, api_v1.EventTypeWarning, "Rejected", "GlobalConfiguration %v is invalid and was rejected: %v", key, validationErr)
		return
	}

	// GlobalConfiguration configures listeners
	// As a result, a change in a GC might affect all TransportServers

	transportServerExes := lbc.transportServersToTransportServerExes(lbc.getTransportServers())

	updatedTransportServerExes, deletedTransportServerExes, updateErr := lbc.configurator.UpdateGlobalConfiguration(gc, transportServerExes)

	for _, tsEx := range deletedTransportServerExes {
		eventTitle := "Rejected"
		eventType := api_v1.EventTypeWarning
		eventWarningMessage := ""

		if updateErr != nil {
			eventTitle = "RejectedWithError"
			eventWarningMessage = fmt.Sprintf("but was not applied: %v", updateErr)
		}

		lbc.recorder.Eventf(tsEx.TransportServer, eventType, eventTitle, "TransportServer %v/%v references a non-existing listener %v", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, eventWarningMessage)
	}

	eventTitle := "Updated"
	eventType := api_v1.EventTypeNormal
	eventWarningMessage := ""

	if updateErr != nil {
		eventTitle = "UpdatedWithError"
		eventType = api_v1.EventTypeWarning
		eventWarningMessage = fmt.Sprintf("but was not applied: %v", updateErr)
	}

	lbc.recorder.Eventf(gc, eventType, eventTitle, "GlobalConfiguration %v was updated %v", key, eventWarningMessage)

	for _, tsEx := range updatedTransportServerExes {
		lbc.recorder.Eventf(tsEx.TransportServer, eventType, eventTitle, "TransportServer %v/%v was updated %v", tsEx.TransportServer.Namespace, tsEx.TransportServer.Name, eventWarningMessage)
	}
}

func (lbc *LoadBalancerController) syncVirtualServer(task task) {
	key := task.Key
	obj, vsExists, err := lbc.virtualServerLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !vsExists {
		glog.V(2).Infof("Deleting VirtualServer: %v\n", key)

		changes, problems = lbc.configuration.DeleteVirtualServer(key)
	} else {
		glog.V(2).Infof("Adding or Updating VirtualServer: %v\n", key)

		vs := obj.(*conf_v1.VirtualServer)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServer(vs)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) processProblems(problems []ConfigurationProblem) {
	glog.V(3).Infof("Processing %v problems", len(problems))

	for _, p := range problems {
		eventType := api_v1.EventTypeWarning
		lbc.recorder.Event(p.Object, eventType, p.Reason, p.Message)

		if lbc.reportVsVsrStatusEnabled() {
			state := conf_v1.StateWarning
			if p.IsError {
				state = conf_v1.StateInvalid
			}

			switch obj := p.Object.(type) {
			case *networking.Ingress:
				err := lbc.statusUpdater.ClearIngressStatus(*obj)
				if err != nil {
					glog.V(3).Infof("Error when updating the status for Ingress %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			case *conf_v1.VirtualServer:
				err := lbc.statusUpdater.UpdateVirtualServerStatus(obj, state, p.Reason, p.Message)
				if err != nil {
					glog.Errorf("Error when updating the status for VirtualServer %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			case *conf_v1.VirtualServerRoute:
				var emptyVSes []*conf_v1.VirtualServer
				err := lbc.statusUpdater.UpdateVirtualServerRouteStatusWithReferencedBy(obj, state, p.Reason, p.Message, emptyVSes)
				if err != nil {
					glog.Errorf("Error when updating the status for VirtualServerRoute %v/%v: %v", obj.Namespace, obj.Name, err)
				}
			}
		}
	}
}

func (lbc *LoadBalancerController) processChanges(changes []ResourceChange) {
	glog.V(3).Infof("Processing %v changes", len(changes))

	for _, c := range changes {
		if c.Op == AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				vsEx := lbc.createVirtualServerEx(impl.VirtualServer, impl.VirtualServerRoutes)

				warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateVirtualServer(vsEx)
				lbc.updateVirtualServerStatusAndEvents(impl, warnings, addOrUpdateErr)
			case *IngressConfiguration:
				if impl.IsMaster {
					mergeableIng := lbc.createMergeableIngresses(impl)

					warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateMergeableIngress(mergeableIng)
					lbc.updateMergeableIngressStatusAndEvents(impl, warnings, addOrUpdateErr)
				} else {
					// for regular Ingress, validMinionPaths is nil
					ingEx := lbc.createIngressEx(impl.Ingress, impl.ValidHosts, nil)

					warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateIngress(ingEx)
					lbc.updateRegularIngressStatusAndEvents(impl, warnings, addOrUpdateErr)
				}
			}
		} else if c.Op == Delete {
			switch impl := c.Resource.(type) {
			case *VirtualServerConfiguration:
				key := getResourceKey(&impl.VirtualServer.ObjectMeta)

				deleteErr := lbc.configurator.DeleteVirtualServer(key)
				if deleteErr != nil {
					glog.Errorf("Error when deleting configuration for VirtualServer %v: %v", key, deleteErr)
				}

				_, vsExists, err := lbc.virtualServerLister.GetByKey(key)
				if err != nil {
					glog.Errorf("Error when getting VirtualServer for %v: %v", key, err)
				}

				if vsExists {
					lbc.UpdateVirtualServerStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			case *IngressConfiguration:
				key := getResourceKey(&impl.Ingress.ObjectMeta)

				glog.V(2).Infof("Deleting Ingress: %v\n", key)

				deleteErr := lbc.configurator.DeleteIngress(key)
				if deleteErr != nil {
					glog.Errorf("Error when deleting configuration for Ingress %v: %v", key, deleteErr)
				}

				_, ingExists, err := lbc.ingressLister.GetByKeySafe(key)
				if err != nil {
					glog.Errorf("Error when getting Ingress for %v: %v", key, err)
				}

				if ingExists {
					lbc.UpdateIngressStatusAndEventsOnDelete(impl, c.Error, deleteErr)
				}
			}
		}
	}
}

func (lbc *LoadBalancerController) processAppProtectChanges(changes []AppProtectChange) {
	glog.V(3).Infof("Processing %v App Protect changes", len(changes))

	for _, c := range changes {
		if c.Op == AddOrUpdate {
			switch impl := c.Resource.(type) {
			case *AppProtectPolicyEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectPolicy(namespace, name)

				ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)

				warnings, updateErr := lbc.configurator.AddOrUpdateAppProtectResource(impl.Obj, ingressExes, mergeableIngresses)
				lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
				lbc.recorder.Eventf(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", "AppProtectPolicy %v was added or updated", namespace+"/"+name)
			case *AppProtectLogConfEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectLogConf(namespace, name)

				ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)

				warnings, updateErr := lbc.configurator.AddOrUpdateAppProtectResource(impl.Obj, ingressExes, mergeableIngresses)
				lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)
				lbc.recorder.Eventf(impl.Obj, api_v1.EventTypeNormal, "AddedOrUpdated", "AppProtectLogConfig  %v was added or updated", namespace+"/"+name)
			}
		} else if c.Op == Delete {
			switch impl := c.Resource.(type) {
			case *AppProtectPolicyEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectPolicy(namespace, name)

				ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)

				warnings, deleteErr := lbc.configurator.DeleteAppProtectPolicy(namespace+"/"+name, ingressExes, mergeableIngresses)

				lbc.updateResourcesStatusAndEvents(resources, warnings, deleteErr)

			case *AppProtectLogConfEx:
				namespace := impl.Obj.GetNamespace()
				name := impl.Obj.GetName()
				resources := lbc.configuration.FindResourcesForAppProtectLogConf(namespace, name)

				ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)

				warnings, deleteErr := lbc.configurator.DeleteAppProtectLogConf(namespace+"/"+name, ingressExes, mergeableIngresses)

				lbc.updateResourcesStatusAndEvents(resources, warnings, deleteErr)
			}
		}
	}
}

func (lbc *LoadBalancerController) processAppProtectUserSigChange(change AppProtectUserSigChange) {
	var delPols []string
	var allIngExes []*configs.IngressEx
	var allMergeableIngresses []*configs.MergeableIngresses
	var allResources []Resource

	for _, poladd := range change.PolicyAddsOrUpdates {
		resources := lbc.configuration.FindResourcesForAppProtectPolicy(poladd.GetNamespace(), poladd.GetName())
		ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)
		allIngExes = append(allIngExes, ingressExes...)
		allMergeableIngresses = append(allMergeableIngresses, mergeableIngresses...)
		allResources = append(allResources, resources...)
	}
	for _, poldel := range change.PolicyDeletions {
		polNsName := getNsName(poldel)
		resources := lbc.configuration.FindResourcesForAppProtectPolicy(poldel.GetNamespace(), poldel.GetName())
		ingressExes, mergeableIngresses, _ := lbc.createExtendedResources(resources)
		allIngExes = append(allIngExes, ingressExes...)
		allMergeableIngresses = append(allMergeableIngresses, mergeableIngresses...)
		allResources = append(allResources, resources...)
		if len(ingressExes) > 0 || len(mergeableIngresses) > 0 {
			delPols = append(delPols, polNsName)
		}
	}

	warnings, err := lbc.configurator.RefreshAppProtectUserSigs(change.UserSigs, delPols, allIngExes, allMergeableIngresses)
	if err != nil {
		glog.Errorf("Error when refreshing App Protect Policy User defined signatures: %v", err)
	}
	lbc.updateResourcesStatusAndEvents(allResources, warnings, err)
}

func (lbc *LoadBalancerController) processAppProtectProblems(problems []AppProtectProblem) {
	glog.V(3).Infof("Processing %v App Protet problems", len(problems))

	for _, p := range problems {
		eventType := api_v1.EventTypeWarning
		lbc.recorder.Event(p.Object, eventType, p.Reason, p.Message)
	}
}

func (lbc *LoadBalancerController) UpdateVirtualServerStatusAndEventsOnDelete(vsConfig *VirtualServerConfiguration, changeError string, deleteErr error) {
	eventType := api_v1.EventTypeWarning
	eventTitle := "Rejected"
	eventWarningMessage := ""
	state := ""

	// VirtualServer either became invalid or lost its host
	if changeError != "" {
		eventWarningMessage = fmt.Sprintf("with error: %s", changeError)
		state = conf_v1.StateInvalid
	} else if len(vsConfig.Warnings) > 0 {
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(vsConfig.Warnings))
		state = conf_v1.StateWarning
	}

	// we don't need to report anything if eventWarningMessage is empty
	// in that case, the resource was deleted because its class became incorrect
	// (some other Ingress Controller will handle it)
	if eventWarningMessage != "" {
		if deleteErr != nil {
			eventType = api_v1.EventTypeWarning
			eventTitle = "RejectedWithError"
			eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, deleteErr)
			state = conf_v1.StateInvalid
		}

		msg := fmt.Sprintf("VirtualServer %s was rejected %s", getResourceKey(&vsConfig.VirtualServer.ObjectMeta), eventWarningMessage)
		lbc.recorder.Eventf(vsConfig.VirtualServer, eventType, eventTitle, msg)

		if lbc.reportVsVsrStatusEnabled() {
			err := lbc.statusUpdater.UpdateVirtualServerStatus(vsConfig.VirtualServer, state, eventTitle, msg)

			if err != nil {
				glog.Errorf("Error when updating the status for VirtualServer %v/%v: %v", vsConfig.VirtualServer.Namespace, vsConfig.VirtualServer.Name, err)
			}
		}
	}

	// for delete, no need to report VirtualServerRoutes
	// for each VSR, a dedicated problem exists
}

func (lbc *LoadBalancerController) UpdateIngressStatusAndEventsOnDelete(ingConfig *IngressConfiguration, changeError string, deleteErr error) {
	eventTitle := "Rejected"
	eventWarningMessage := ""

	// Ingress either became invalid or lost all its hosts
	if changeError != "" {
		eventWarningMessage = fmt.Sprintf("with error: %s", changeError)
	} else if len(ingConfig.Warnings) > 0 {
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
	}

	// we don't need to report anything if eventWarningMessage is empty
	// in that case, the resource was deleted because its class became incorrect
	// (some other Ingress Controller will handle it)
	if eventWarningMessage != "" {
		if deleteErr != nil {
			eventTitle = "RejectedWithError"
			eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, deleteErr)
		}

		lbc.recorder.Eventf(ingConfig.Ingress, api_v1.EventTypeWarning, eventTitle, "%v was rejected: %v", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningMessage)
		if lbc.reportStatusEnabled() {
			err := lbc.statusUpdater.ClearIngressStatus(*ingConfig.Ingress)
			if err != nil {
				glog.V(3).Infof("Error clearing Ingress status: %v", err)
			}
		}
	}

	// for delete, no need to report minions
	// for each minion, a dedicated problem exists
}

func (lbc *LoadBalancerController) updateResourcesStatusAndEvents(resources []Resource, warnings configs.Warnings, operationErr error) {
	for _, r := range resources {
		switch impl := r.(type) {
		case *VirtualServerConfiguration:
			lbc.updateVirtualServerStatusAndEvents(impl, warnings, operationErr)
		case *IngressConfiguration:
			if impl.IsMaster {
				lbc.updateMergeableIngressStatusAndEvents(impl, warnings, operationErr)
			} else {
				lbc.updateRegularIngressStatusAndEvents(impl, warnings, operationErr)
			}
		}
	}
}

func (lbc *LoadBalancerController) updateMergeableIngressStatusAndEvents(ingConfig *IngressConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := "AddedOrUpdated"
	eventWarningMessage := ""

	if len(ingConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
	}

	if messages, ok := warnings[ingConfig.Ingress]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", eventWarningMessage, formatWarningMessages(messages))
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithError"
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(ingConfig.Ingress, eventType, eventTitle, msg)

	for _, fm := range ingConfig.Minions {
		minionEventType := api_v1.EventTypeNormal
		minionEventTitle := "AddedOrUpdated"
		minionEventWarningMessage := ""

		minionChangeWarnings := ingConfig.ChildWarnings[getResourceKey(&fm.Ingress.ObjectMeta)]
		if len(minionChangeWarnings) > 0 {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = "AddedOrUpdatedWithWarning"
			minionEventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(minionChangeWarnings))
		}

		if messages, ok := warnings[fm.Ingress]; ok {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = "AddedOrUpdatedWithWarning"
			minionEventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", minionEventWarningMessage, formatWarningMessages(messages))
		}

		if operationErr != nil {
			minionEventType = api_v1.EventTypeWarning
			minionEventTitle = "AddedOrUpdatedWithError"
			minionEventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", minionEventWarningMessage, operationErr)
		}

		minionMsg := fmt.Sprintf("Configuration for %v/%v was added or updated %s", fm.Ingress.Namespace, fm.Ingress.Name, minionEventWarningMessage)
		lbc.recorder.Eventf(fm.Ingress, minionEventType, minionEventTitle, minionMsg)
	}

	if lbc.reportStatusEnabled() {
		ings := []networking.Ingress{*ingConfig.Ingress}

		for _, fm := range ingConfig.Minions {
			ings = append(ings, *fm.Ingress)
		}

		err := lbc.statusUpdater.BulkUpdateIngressStatus(ings)
		if err != nil {
			glog.V(3).Infof("error updating ing status: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) updateRegularIngressStatusAndEvents(ingConfig *IngressConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := "AddedOrUpdated"
	eventWarningMessage := ""

	if len(ingConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(ingConfig.Warnings))
	}

	if messages, ok := warnings[ingConfig.Ingress]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", eventWarningMessage, formatWarningMessages(messages))
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithError"
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&ingConfig.Ingress.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(ingConfig.Ingress, eventType, eventTitle, msg)

	if lbc.reportStatusEnabled() {
		err := lbc.statusUpdater.UpdateIngressStatus(*ingConfig.Ingress)
		if err != nil {
			glog.V(3).Infof("error updating ing status: %v", err)
		}
	}
}

func (lbc *LoadBalancerController) updateVirtualServerStatusAndEvents(vsConfig *VirtualServerConfiguration, warnings configs.Warnings, operationErr error) {
	eventType := api_v1.EventTypeNormal
	eventTitle := "AddedOrUpdated"
	eventWarningMessage := ""
	state := conf_v1.StateValid

	if len(vsConfig.Warnings) > 0 {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(vsConfig.Warnings))
		state = conf_v1.StateWarning
	}

	if messages, ok := warnings[vsConfig.VirtualServer]; ok {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithWarning"
		eventWarningMessage = fmt.Sprintf("%s; with warning(s): %v", eventWarningMessage, formatWarningMessages(messages))
		state = conf_v1.StateWarning
	}

	if operationErr != nil {
		eventType = api_v1.EventTypeWarning
		eventTitle = "AddedOrUpdatedWithError"
		eventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", eventWarningMessage, operationErr)
		state = conf_v1.StateInvalid
	}

	msg := fmt.Sprintf("Configuration for %v was added or updated %s", getResourceKey(&vsConfig.VirtualServer.ObjectMeta), eventWarningMessage)
	lbc.recorder.Eventf(vsConfig.VirtualServer, eventType, eventTitle, msg)

	if lbc.reportVsVsrStatusEnabled() {
		err := lbc.statusUpdater.UpdateVirtualServerStatus(vsConfig.VirtualServer, state, eventTitle, msg)
		if err != nil {
			glog.Errorf("Error when updating the status for VirtualServer %v/%v: %v", vsConfig.VirtualServer.Namespace, vsConfig.VirtualServer.Name, err)
		}
	}

	for _, vsr := range vsConfig.VirtualServerRoutes {
		vsrEventType := api_v1.EventTypeNormal
		vsrEventTitle := "AddedOrUpdated"
		vsrEventWarningMessage := ""
		vsrState := conf_v1.StateValid

		if messages, ok := warnings[vsr]; ok {
			vsrEventType = api_v1.EventTypeWarning
			vsrEventTitle = "AddedOrUpdatedWithWarning"
			vsrEventWarningMessage = fmt.Sprintf("with warning(s): %v", formatWarningMessages(messages))
			vsrState = conf_v1.StateWarning
		}

		if operationErr != nil {
			vsrEventType = api_v1.EventTypeWarning
			vsrEventTitle = "AddedOrUpdatedWithError"
			vsrEventWarningMessage = fmt.Sprintf("%s; but was not applied: %v", vsrEventWarningMessage, operationErr)
			vsrState = conf_v1.StateInvalid
		}

		msg := fmt.Sprintf("Configuration for %v/%v was added or updated %s", vsr.Namespace, vsr.Name, vsrEventWarningMessage)
		lbc.recorder.Eventf(vsr, vsrEventType, vsrEventTitle, msg)

		if lbc.reportVsVsrStatusEnabled() {
			vss := []*conf_v1.VirtualServer{vsConfig.VirtualServer}
			err := lbc.statusUpdater.UpdateVirtualServerRouteStatusWithReferencedBy(vsr, vsrState, vsrEventTitle, msg, vss)
			if err != nil {
				glog.Errorf("Error when updating the status for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}
		}
	}
}

func (lbc *LoadBalancerController) syncVirtualServerRoute(task task) {
	key := task.Key
	obj, exists, err := lbc.virtualServerRouteLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !exists {
		glog.V(2).Infof("Deleting VirtualServerRoute: %v\n", key)

		changes, problems = lbc.configuration.DeleteVirtualServerRoute(key)
	} else {
		glog.V(2).Infof("Adding or Updating VirtualServerRoute: %v\n", key)

		vsr := obj.(*conf_v1.VirtualServerRoute)
		changes, problems = lbc.configuration.AddOrUpdateVirtualServerRoute(vsr)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) syncIngress(task task) {
	key := task.Key
	ing, ingExists, err := lbc.ingressLister.GetByKeySafe(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []ResourceChange
	var problems []ConfigurationProblem

	if !ingExists {
		glog.V(2).Infof("Deleting Ingress: %v\n", key)

		changes, problems = lbc.configuration.DeleteIngress(key)
	} else {
		glog.V(2).Infof("Adding or Updating Ingress: %v\n", key)

		changes, problems = lbc.configuration.AddOrUpdateIngress(ing)
	}

	lbc.processChanges(changes)
	lbc.processProblems(problems)
}

func (lbc *LoadBalancerController) updateIngressMetrics() {
	counters := lbc.configurator.GetIngressCounts()
	for nType, count := range counters {
		lbc.metricsCollector.SetIngresses(nType, count)
	}
}

func (lbc *LoadBalancerController) updateVirtualServerMetrics() {
	vsCount, vsrCount := lbc.configurator.GetVirtualServerCounts()
	lbc.metricsCollector.SetVirtualServers(vsCount)
	lbc.metricsCollector.SetVirtualServerRoutes(vsrCount)
}

func (lbc *LoadBalancerController) syncService(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing service %v", key)

	obj, exists, err := lbc.svcLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	// First case: the service is the external service for the Ingress Controller
	// In that case we need to update the statuses of all resources

	if lbc.IsExternalServiceKeyForStatus(key) {

		if !exists {
			// service got removed
			lbc.statusUpdater.ClearStatusFromExternalService()
		} else {
			// service added or updated
			lbc.statusUpdater.SaveStatusFromExternalService(obj.(*api_v1.Service))
		}

		if lbc.reportStatusEnabled() {
			ingresses := lbc.configuration.GetResourcesWithFilter(resourceFilter{Ingresses: true})

			glog.V(3).Infof("Updating status for %v Ingresses", len(ingresses))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(ingresses)
			if err != nil {
				glog.Errorf("error updating ingress status in syncService: %v", err)
			}
		}

		if lbc.areCustomResourcesEnabled && lbc.reportVsVsrStatusEnabled() {
			virtualServers := lbc.configuration.GetResourcesWithFilter(resourceFilter{VirtualServers: true})

			glog.V(3).Infof("Updating status for %v VirtualServers", len(virtualServers))

			err := lbc.statusUpdater.UpdateExternalEndpointsForResources(virtualServers)
			if err != nil {
				glog.V(3).Infof("error updating VirtualServer/VirtualServerRoute status in syncService: %v", err)
			}
		}

		// we don't return here because technically the same service could be used in the second case
	}

	// Second case: the service is referenced by some resources in the cluster

	// it is safe to ignore the error
	namespace, name, _ := ParseNamespaceName(key)

	resources := lbc.configuration.FindResourcesForService(namespace, name)

	if len(resources) == 0 {
		return
	}

	glog.V(3).Infof("Updating %v resources", len(resources))

	ingressExes, mergeableIngresses, virtualServerExes := lbc.createExtendedResources(resources)

	warnings, updateErr := lbc.configurator.AddOrUpdateResources(ingressExes, mergeableIngresses, virtualServerExes)
	lbc.updateResourcesStatusAndEvents(resources, warnings, updateErr)

	// TransportServers are processed separately: each affected TS gets enqueued in service handlers
}

// IsExternalServiceForStatus matches the service specified by the external-service cli arg
func (lbc *LoadBalancerController) IsExternalServiceForStatus(svc *api_v1.Service) bool {
	return lbc.statusUpdater.namespace == svc.Namespace && lbc.statusUpdater.externalServiceName == svc.Name
}

// IsExternalServiceKeyForStatus matches the service key specified by the external-service cli arg
func (lbc *LoadBalancerController) IsExternalServiceKeyForStatus(key string) bool {
	externalSvcKey := fmt.Sprintf("%s/%s", lbc.statusUpdater.namespace, lbc.statusUpdater.externalServiceName)
	return key == externalSvcKey
}

// reportStatusEnabled determines if we should attempt to report status for Ingress resources.
func (lbc *LoadBalancerController) reportStatusEnabled() bool {
	if lbc.reportIngressStatus {
		if lbc.isLeaderElectionEnabled {
			return lbc.leaderElector != nil && lbc.leaderElector.IsLeader()
		}
		return true
	}
	return false
}

// reportVsVsrStatusEnabled determines if we should attempt to report status for VirtualServers and VirtualServerRoutes.
func (lbc *LoadBalancerController) reportVsVsrStatusEnabled() bool {
	if lbc.isLeaderElectionEnabled {
		return lbc.leaderElector != nil && lbc.leaderElector.IsLeader()
	}

	return true
}

func (lbc *LoadBalancerController) syncSecret(task task) {
	key := task.Key
	obj, secrExists, err := lbc.secretLister.Store.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	namespace, name, err := ParseNamespaceName(key)
	if err != nil {
		glog.Warningf("Secret key %v is invalid: %v", key, err)
		return
	}

	resources := lbc.configuration.FindResourcesForSecret(namespace, name)

	if lbc.areCustomResourcesEnabled {
		secretPols := lbc.getPoliciesForSecret(namespace, name)
		for _, pol := range secretPols {
			resources = append(resources, lbc.configuration.FindResourcesForPolicy(pol.Namespace, pol.Name)...)
		}

		resources = removeDuplicateResources(resources)
	}

	glog.V(2).Infof("Found %v Resources with Secret %v", len(resources), key)

	if !secrExists {
		lbc.secretStore.DeleteSecret(key)

		glog.V(2).Infof("Deleting Secret: %v\n", key)

		if len(resources) > 0 {
			lbc.handleRegularSecretDeletion(resources)
		}
		if lbc.isSpecialSecret(key) {
			glog.Warningf("A special TLS Secret %v was removed. Retaining the Secret.", key)
		}
		return
	}

	glog.V(2).Infof("Adding / Updating Secret: %v\n", key)

	secret := obj.(*api_v1.Secret)

	lbc.secretStore.AddOrUpdateSecret(secret)

	if lbc.isSpecialSecret(key) {
		lbc.handleSpecialSecretUpdate(secret)
		// we don't return here in case the special secret is also used in resources.
	}

	if len(resources) > 0 {
		lbc.handleSecretUpdate(secret, resources)
	}
}

func removeDuplicateResources(resources []Resource) []Resource {
	encountered := make(map[string]bool)
	var uniqueResources []Resource
	for _, r := range resources {
		key := r.GetKeyWithKind()
		if !encountered[key] {
			encountered[key] = true
			uniqueResources = append(uniqueResources, r)
		}
	}

	return uniqueResources
}

func (lbc *LoadBalancerController) isSpecialSecret(secretName string) bool {
	return secretName == lbc.defaultServerSecret || secretName == lbc.wildcardTLSSecret
}

func (lbc *LoadBalancerController) handleRegularSecretDeletion(resources []Resource) {
	ingressExes, mergeableIngresses, virtualServerExes := lbc.createExtendedResources(resources)

	warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateResources(ingressExes, mergeableIngresses, virtualServerExes)

	lbc.updateResourcesStatusAndEvents(resources, warnings, addOrUpdateErr)
}

func (lbc *LoadBalancerController) handleSecretUpdate(secret *api_v1.Secret, resources []Resource) {
	secretNsName := secret.Namespace + "/" + secret.Name

	var warnings configs.Warnings
	var addOrUpdateErr error

	ingressExes, mergeableIngresses, virtualServerExes := lbc.createExtendedResources(resources)
	warnings, addOrUpdateErr = lbc.configurator.AddOrUpdateResources(ingressExes, mergeableIngresses, virtualServerExes)

	if addOrUpdateErr != nil {
		glog.Errorf("Error when updating Secret %v: %v", secretNsName, addOrUpdateErr)
		lbc.recorder.Eventf(secret, api_v1.EventTypeWarning, "UpdatedWithError", "%v was updated, but not applied: %v", secretNsName, addOrUpdateErr)
	}

	lbc.updateResourcesStatusAndEvents(resources, warnings, addOrUpdateErr)
}

func (lbc *LoadBalancerController) handleSpecialSecretUpdate(secret *api_v1.Secret) {
	var specialSecretsToUpdate []string
	secretNsName := secret.Namespace + "/" + secret.Name
	err := secrets.ValidateTLSSecret(secret)
	if err != nil {
		glog.Errorf("Couldn't validate the special Secret %v: %v", secretNsName, err)
		lbc.recorder.Eventf(secret, api_v1.EventTypeWarning, "Rejected", "the special Secret %v was rejected, using the previous version: %v", secretNsName, err)
		return
	}

	if secretNsName == lbc.defaultServerSecret {
		specialSecretsToUpdate = append(specialSecretsToUpdate, configs.DefaultServerSecretName)
	}
	if secretNsName == lbc.wildcardTLSSecret {
		specialSecretsToUpdate = append(specialSecretsToUpdate, configs.WildcardSecretName)
	}

	err = lbc.configurator.AddOrUpdateSpecialTLSSecrets(secret, specialSecretsToUpdate)
	if err != nil {
		glog.Errorf("Error when updating the special Secret %v: %v", secretNsName, err)
		lbc.recorder.Eventf(secret, api_v1.EventTypeWarning, "UpdatedWithError", "the special Secret %v was updated, but not applied: %v", secretNsName, err)
		return
	}

	lbc.recorder.Eventf(secret, api_v1.EventTypeNormal, "Updated", "the special Secret %v was updated", secretNsName)
}

func getStatusFromEventTitle(eventTitle string) string {
	switch eventTitle {
	case "AddedOrUpdatedWithError", "Rejected", "NoVirtualServersFound", "Missing Secret", "UpdatedWithError":
		return conf_v1.StateInvalid
	case "AddedOrUpdatedWithWarning", "UpdatedWithWarning":
		return conf_v1.StateWarning
	case "AddedOrUpdated", "Updated":
		return conf_v1.StateValid
	}

	return ""
}

func (lbc *LoadBalancerController) updateVirtualServersStatusFromEvents() error {
	var allErrs []error
	for _, obj := range lbc.virtualServerLister.List() {
		vs := obj.(*conf_v1.VirtualServer)

		if !lbc.HasCorrectIngressClass(vs) {
			glog.V(3).Infof("Ignoring VirtualServer %v based on class %v", vs.Name, vs.Spec.IngressClass)
			continue
		}

		events, err := lbc.client.CoreV1().Events(vs.Namespace).List(context.TODO(),
			meta_v1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%v,involvedObject.uid=%v", vs.Name, vs.UID)})
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("error trying to get events for VirtualServer %v/%v: %v", vs.Namespace, vs.Name, err))
			break
		}

		if len(events.Items) == 0 {
			continue
		}

		var timestamp time.Time
		var latestEvent api_v1.Event
		for _, event := range events.Items {
			if event.CreationTimestamp.After(timestamp) {
				latestEvent = event
			}
		}

		err = lbc.statusUpdater.UpdateVirtualServerStatus(vs, getStatusFromEventTitle(latestEvent.Reason), latestEvent.Reason, latestEvent.Message)
		if err != nil {
			allErrs = append(allErrs, err)
		}
	}

	if len(allErrs) > 0 {
		return fmt.Errorf("not all VirtualServers statuses were updated: %v", allErrs)
	}

	return nil
}

func (lbc *LoadBalancerController) updateVirtualServerRoutesStatusFromEvents() error {
	var allErrs []error
	for _, obj := range lbc.virtualServerRouteLister.List() {
		vsr := obj.(*conf_v1.VirtualServerRoute)

		if !lbc.HasCorrectIngressClass(vsr) {
			glog.V(3).Infof("Ignoring VirtualServerRoute %v based on class %v", vsr.Name, vsr.Spec.IngressClass)
			continue
		}

		events, err := lbc.client.CoreV1().Events(vsr.Namespace).List(context.TODO(),
			meta_v1.ListOptions{FieldSelector: fmt.Sprintf("involvedObject.name=%v,involvedObject.uid=%v", vsr.Name, vsr.UID)})
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("error trying to get events for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err))
			break
		}

		if len(events.Items) == 0 {
			continue
		}

		var timestamp time.Time
		var latestEvent api_v1.Event
		for _, event := range events.Items {
			if event.CreationTimestamp.After(timestamp) {
				latestEvent = event
			}
		}

		err = lbc.statusUpdater.UpdateVirtualServerRouteStatus(vsr, getStatusFromEventTitle(latestEvent.Reason), latestEvent.Reason, latestEvent.Message)
		if err != nil {
			allErrs = append(allErrs, err)
		}
	}

	if len(allErrs) > 0 {
		return fmt.Errorf("not all VirtualServerRoutes statuses were updated: %v", allErrs)
	}

	return nil
}

// EnqueueTransportServerForService enqueues TransportServers for the given service.
func (lbc *LoadBalancerController) EnqueueTransportServerForService(service *api_v1.Service) {
	transportServers := lbc.getTransportServersForService(service)
	for _, ts := range transportServers {
		lbc.syncQueue.Enqueue(ts)
	}
}

func (lbc *LoadBalancerController) getTransportServersForEndpoints(endpoints *api_v1.Endpoints) []*conf_v1alpha1.TransportServer {
	svcKey := fmt.Sprintf("%s/%s", endpoints.Namespace, endpoints.Name)

	svc, exists, err := lbc.svcLister.GetByKey(svcKey)
	if err != nil {
		glog.V(3).Infof("Error getting service %v from the cache: %v", svcKey, err)
		return nil
	}
	if !exists {
		glog.V(3).Infof("Service %v doesn't exist", svcKey)
		return nil
	}

	return lbc.getTransportServersForService(svc.(*api_v1.Service))
}

func (lbc *LoadBalancerController) getTransportServersForService(service *api_v1.Service) []*conf_v1alpha1.TransportServer {
	filtered := lbc.filterOutTransportServersWithNonExistingListener(lbc.getTransportServers())
	return findTransportServersForService(filtered, service)
}

func findTransportServersForService(transportServers []*conf_v1alpha1.TransportServer, service *api_v1.Service) []*conf_v1alpha1.TransportServer {
	var result []*conf_v1alpha1.TransportServer

	for _, ts := range transportServers {
		if ts.Namespace != service.Namespace {
			continue
		}

		for _, u := range ts.Spec.Upstreams {
			if u.Service == service.Name {
				result = append(result, ts)
				break
			}
		}
	}

	return result
}

func (lbc *LoadBalancerController) filterOutTransportServersWithNonExistingListener(transportServers []*conf_v1alpha1.TransportServer) []*conf_v1alpha1.TransportServer {
	var result []*conf_v1alpha1.TransportServer

	for _, ts := range transportServers {
		if lbc.configurator.CheckIfListenerExists(&ts.Spec.Listener) {
			result = append(result, ts)
		} else {
			glog.V(3).Infof("Ignoring TransportServer %s/%s references a non-existing listener", ts.Namespace, ts.Name)
		}
	}

	return result
}

func (lbc *LoadBalancerController) getTransportServers() []*conf_v1alpha1.TransportServer {
	var transportServers []*conf_v1alpha1.TransportServer

	for _, obj := range lbc.transportServerLister.List() {
		ts := obj.(*conf_v1alpha1.TransportServer)

		err := lbc.transportServerValidator.ValidateTransportServer(ts)
		if err != nil {
			glog.V(3).Infof("Skipping invalid TransportServer %s/%s: %v", ts.Namespace, ts.Name, err)
			continue
		}

		transportServers = append(transportServers, ts)
	}

	return transportServers
}

func getIPAddressesFromEndpoints(endpoints []podEndpoint) []string {
	var endps []string
	for _, ep := range endpoints {
		endps = append(endps, ep.Address)
	}
	return endps
}

func (lbc *LoadBalancerController) createMergeableIngresses(ingConfig *IngressConfiguration) *configs.MergeableIngresses {
	// for master Ingress, validMinionPaths are nil
	masterIngressEx := lbc.createIngressEx(ingConfig.Ingress, ingConfig.ValidHosts, nil)

	var minions []*configs.IngressEx

	for _, m := range ingConfig.Minions {
		minions = append(minions, lbc.createIngressEx(m.Ingress, ingConfig.ValidHosts, m.ValidPaths))
	}

	return &configs.MergeableIngresses{
		Master:  masterIngressEx,
		Minions: minions,
	}
}

func (lbc *LoadBalancerController) createIngressEx(ing *networking.Ingress, validHosts map[string]bool, validMinionPaths map[string]bool) *configs.IngressEx {
	ingEx := &configs.IngressEx{
		Ingress:          ing,
		ValidHosts:       validHosts,
		ValidMinionPaths: validMinionPaths,
	}

	ingEx.SecretRefs = make(map[string]*secrets.SecretReference)

	for _, tls := range ing.Spec.TLS {
		secretName := tls.SecretName
		secretKey := ing.Namespace + "/" + secretName

		secretRef := lbc.secretStore.GetSecretReference(secretKey)
		if secretRef.Error != nil {
			glog.Warningf("Error trying to get the secret %v for Ingress %v: %v", secretName, ing.Name, secretRef.Error)
		}

		ingEx.SecretRefs[secretName] = secretRef
	}

	if lbc.isNginxPlus {
		if jwtKey, exists := ingEx.Ingress.Annotations[configs.JWTKeyAnnotation]; exists {
			secretName := jwtKey
			secretKey := ing.Namespace + "/" + secretName

			secretRef := lbc.secretStore.GetSecretReference(secretKey)
			if secretRef.Error != nil {
				glog.Warningf("Error trying to get the secret %v for Ingress %v/%v: %v", secretName, ing.Namespace, ing.Name, secretRef.Error)
			}

			ingEx.SecretRefs[secretName] = secretRef
		}
		if lbc.appProtectEnabled {
			if apPolicyAntn, exists := ingEx.Ingress.Annotations[configs.AppProtectPolicyAnnotation]; exists {
				policy, err := lbc.getAppProtectPolicy(ing)
				if err != nil {
					glog.Warningf("Error Getting App Protect policy %v for Ingress %v/%v: %v", apPolicyAntn, ing.Namespace, ing.Name, err)
				} else {
					ingEx.AppProtectPolicy = policy
				}
			}

			if apLogConfAntn, exists := ingEx.Ingress.Annotations[configs.AppProtectLogConfAnnotation]; exists {
				logConf, logDst, err := lbc.getAppProtectLogConfAndDst(ing)
				if err != nil {
					glog.Warningf("Error Getting App Protect policy %v for Ingress %v/%v: %v", apLogConfAntn, ing.Namespace, ing.Name, err)
				} else {
					ingEx.AppProtectLogConf = logConf
					ingEx.AppProtectLogDst = logDst
				}
			}
		}
	}

	ingEx.Endpoints = make(map[string][]string)
	ingEx.HealthChecks = make(map[string]*api_v1.Probe)
	ingEx.ExternalNameSvcs = make(map[string]bool)
	ingEx.PodsByIP = make(map[string]configs.PodInfo)

	if ing.Spec.Backend != nil {
		podEndps := []podEndpoint{}
		var external bool
		svc, err := lbc.getServiceForIngressBackend(ing.Spec.Backend, ing.Namespace)
		if err != nil {
			glog.V(3).Infof("Error getting service %v: %v", ing.Spec.Backend.ServiceName, err)
		} else {
			podEndps, external, err = lbc.getEndpointsForIngressBackend(ing.Spec.Backend, svc)
			if err == nil && external && lbc.isNginxPlus {
				ingEx.ExternalNameSvcs[svc.Name] = true
			}
		}

		if err != nil {
			glog.Warningf("Error retrieving endpoints for the service %v: %v", ing.Spec.Backend.ServiceName, err)
		}

		endps := getIPAddressesFromEndpoints(podEndps)

		// endps is empty if there was any error before this point
		ingEx.Endpoints[ing.Spec.Backend.ServiceName+ing.Spec.Backend.ServicePort.String()] = endps

		if lbc.isNginxPlus && lbc.isHealthCheckEnabled(ing) {
			healthCheck := lbc.getHealthChecksForIngressBackend(ing.Spec.Backend, ing.Namespace)
			if healthCheck != nil {
				ingEx.HealthChecks[ing.Spec.Backend.ServiceName+ing.Spec.Backend.ServicePort.String()] = healthCheck
			}
		}

		if (lbc.isNginxPlus && lbc.isPrometheusEnabled) || lbc.isLatencyMetricsEnabled {
			for _, endpoint := range podEndps {
				ingEx.PodsByIP[endpoint.Address] = configs.PodInfo{
					Name:         endpoint.PodName,
					MeshPodOwner: endpoint.MeshPodOwner,
				}
			}
		}
	}

	for _, rule := range ing.Spec.Rules {
		if !validHosts[rule.Host] {
			glog.V(3).Infof("Skipping host %s for Ingress %s", rule.Host, ing.Name)
			continue
		}

		// check if rule has any paths
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}

		for _, path := range rule.HTTP.Paths {
			podEndps := []podEndpoint{}
			if validMinionPaths != nil && !validMinionPaths[path.Path] {
				glog.V(3).Infof("Skipping path %s for minion Ingress %s", path.Path, ing.Name)
				continue
			}

			var external bool
			svc, err := lbc.getServiceForIngressBackend(&path.Backend, ing.Namespace)
			if err != nil {
				glog.V(3).Infof("Error getting service %v: %v", &path.Backend.ServiceName, err)
			} else {
				podEndps, external, err = lbc.getEndpointsForIngressBackend(&path.Backend, svc)
				if err == nil && external && lbc.isNginxPlus {
					ingEx.ExternalNameSvcs[svc.Name] = true
				}
			}

			if err != nil {
				glog.Warningf("Error retrieving endpoints for the service %v: %v", path.Backend.ServiceName, err)
			}

			endps := getIPAddressesFromEndpoints(podEndps)

			// endps is empty if there was any error before this point
			ingEx.Endpoints[path.Backend.ServiceName+path.Backend.ServicePort.String()] = endps

			// Pull active health checks from k8 api
			if lbc.isNginxPlus && lbc.isHealthCheckEnabled(ing) {
				healthCheck := lbc.getHealthChecksForIngressBackend(&path.Backend, ing.Namespace)
				if healthCheck != nil {
					ingEx.HealthChecks[path.Backend.ServiceName+path.Backend.ServicePort.String()] = healthCheck
				}
			}

			if lbc.isNginxPlus || lbc.isLatencyMetricsEnabled {
				for _, endpoint := range podEndps {
					ingEx.PodsByIP[endpoint.Address] = configs.PodInfo{
						Name:         endpoint.PodName,
						MeshPodOwner: endpoint.MeshPodOwner,
					}
				}
			}
		}
	}

	return ingEx
}

func (lbc *LoadBalancerController) getAppProtectLogConfAndDst(ing *networking.Ingress) (logConf *unstructured.Unstructured, logDst string, err error) {
	logConfNsN := ParseResourceReferenceAnnotation(ing.Namespace, ing.Annotations[configs.AppProtectLogConfAnnotation])

	if _, exists := ing.Annotations[configs.AppProtectLogConfDstAnnotation]; !exists {
		return nil, "", fmt.Errorf("Error: %v requires %v in %v", configs.AppProtectLogConfAnnotation, configs.AppProtectLogConfDstAnnotation, ing.Name)
	}

	logDst = ing.Annotations[configs.AppProtectLogConfDstAnnotation]

	err = ValidateAppProtectLogDestinationAnnotation(logDst)

	if err != nil {
		return nil, "", fmt.Errorf("Error Validating App Protect Destination Config for Ingress %v: %v", ing.Name, err)
	}

	logConf, err = lbc.appProtectConfiguration.GetAppResource(appProtectLogConfGVK.Kind, logConfNsN)
	if err != nil {
		return nil, "", fmt.Errorf("Error retrieving App Protect Log Config for Ingress %v: %v", ing.Name, err)
	}

	return logConf, logDst, nil
}

func (lbc *LoadBalancerController) getAppProtectPolicy(ing *networking.Ingress) (apPolicy *unstructured.Unstructured, err error) {
	polNsN := ParseResourceReferenceAnnotation(ing.Namespace, ing.Annotations[configs.AppProtectPolicyAnnotation])

	apPolicy, err = lbc.appProtectConfiguration.GetAppResource(appProtectPolicyGVK.Kind, polNsN)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving App Protect Policy for Ingress %v: %v ", ing.Name, err)
	}

	return apPolicy, nil
}

func (lbc *LoadBalancerController) createVirtualServerEx(virtualServer *conf_v1.VirtualServer, virtualServerRoutes []*conf_v1.VirtualServerRoute) *configs.VirtualServerEx {
	virtualServerEx := configs.VirtualServerEx{
		VirtualServer: virtualServer,
		SecretRefs:    make(map[string]*secrets.SecretReference),
	}

	if virtualServer.Spec.TLS != nil && virtualServer.Spec.TLS.Secret != "" {
		secretKey := virtualServer.Namespace + "/" + virtualServer.Spec.TLS.Secret

		secretRef := lbc.secretStore.GetSecretReference(secretKey)
		if secretRef.Error != nil {
			glog.Warningf("Error trying to get the secret %v for VirtualServer %v: %v", secretKey, virtualServer.Name, secretRef.Error)
		}

		virtualServerEx.SecretRefs[secretKey] = secretRef
	}

	policies, policyErrors := lbc.getPolicies(virtualServer.Spec.Policies, virtualServer.Namespace)
	for _, err := range policyErrors {
		glog.Warningf("Error getting policy for VirtualServer %s/%s: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	err := lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		glog.Warningf("Error getting JWT secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	err = lbc.addIngressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		glog.Warningf("Error getting IngressMTLS secret for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
	if err != nil {
		glog.Warningf("Error getting EgressMTLS secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
	}

	endpoints := make(map[string][]string)
	externalNameSvcs := make(map[string]bool)
	podsByIP := make(map[string]configs.PodInfo)

	for _, u := range virtualServer.Spec.Upstreams {
		endpointsKey := configs.GenerateEndpointsKey(virtualServer.Namespace, u.Service, u.Subselector, u.Port)

		var podEndps []podEndpoint
		var err error

		if len(u.Subselector) > 0 {
			podEndps, err = lbc.getEndpointsForSubselector(virtualServer.Namespace, u)
		} else {
			var external bool
			podEndps, external, err = lbc.getEndpointsForUpstream(virtualServer.Namespace, u.Service, u.Port)

			if err == nil && external && lbc.isNginxPlus {
				externalNameSvcs[configs.GenerateExternalNameSvcKey(virtualServer.Namespace, u.Service)] = true
			}
		}

		if err != nil {
			glog.Warningf("Error getting Endpoints for Upstream %v: %v", u.Name, err)
		}

		endps := getIPAddressesFromEndpoints(podEndps)
		endpoints[endpointsKey] = endps

		if (lbc.isNginxPlus && lbc.isPrometheusEnabled) || lbc.isLatencyMetricsEnabled {
			for _, endpoint := range podEndps {
				podsByIP[endpoint.Address] = configs.PodInfo{
					Name:         endpoint.PodName,
					MeshPodOwner: endpoint.MeshPodOwner,
				}
			}
		}
	}

	for _, r := range virtualServer.Spec.Routes {
		vsRoutePolicies, policyErrors := lbc.getPolicies(r.Policies, virtualServer.Namespace)
		for _, err := range policyErrors {
			glog.Warningf("Error getting policy for VirtualServer %s/%s: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		policies = append(policies, vsRoutePolicies...)

		err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
		if err != nil {
			glog.Warningf("Error getting EgressMTLS secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
		err = lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, vsRoutePolicies)
		if err != nil {
			glog.Warningf("Error getting JWT secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
		}
	}

	for _, vsr := range virtualServerRoutes {
		for _, sr := range vsr.Spec.Subroutes {
			vsrSubroutePolicies, policyErrors := lbc.getPolicies(sr.Policies, vsr.Namespace)
			for _, err := range policyErrors {
				glog.Warningf("Error getting policy for VirtualServerRoute %s/%s: %v", vsr.Namespace, vsr.Name, err)
			}
			policies = append(policies, vsrSubroutePolicies...)

			err = lbc.addJWTSecretRefs(virtualServerEx.SecretRefs, vsrSubroutePolicies)
			if err != nil {
				glog.Warningf("Error getting JWT secrets for VirtualServerRoute %v/%v: %v", vsr.Namespace, vsr.Name, err)
			}

			err = lbc.addEgressMTLSSecretRefs(virtualServerEx.SecretRefs, policies)
			if err != nil {
				glog.Warningf("Error getting EgressMTLS secrets for VirtualServer %v/%v: %v", virtualServer.Namespace, virtualServer.Name, err)
			}
		}

		for _, u := range vsr.Spec.Upstreams {
			endpointsKey := configs.GenerateEndpointsKey(vsr.Namespace, u.Service, u.Subselector, u.Port)

			var podEndps []podEndpoint
			var err error
			if len(u.Subselector) > 0 {
				podEndps, err = lbc.getEndpointsForSubselector(vsr.Namespace, u)
			} else {
				var external bool
				podEndps, external, err = lbc.getEndpointsForUpstream(vsr.Namespace, u.Service, u.Port)

				if err == nil && external && lbc.isNginxPlus {
					externalNameSvcs[configs.GenerateExternalNameSvcKey(vsr.Namespace, u.Service)] = true
				}
			}
			if err != nil {
				glog.Warningf("Error getting Endpoints for Upstream %v: %v", u.Name, err)
			}

			endps := getIPAddressesFromEndpoints(podEndps)
			endpoints[endpointsKey] = endps

			if lbc.isNginxPlus || lbc.isLatencyMetricsEnabled {
				for _, endpoint := range podEndps {
					podsByIP[endpoint.Address] = configs.PodInfo{
						Name:         endpoint.PodName,
						MeshPodOwner: endpoint.MeshPodOwner,
					}
				}
			}
		}
	}

	virtualServerEx.Endpoints = endpoints
	virtualServerEx.VirtualServerRoutes = virtualServerRoutes
	virtualServerEx.ExternalNameSvcs = externalNameSvcs
	virtualServerEx.Policies = createPolicyMap(policies)
	virtualServerEx.PodsByIP = podsByIP

	return &virtualServerEx
}

func createPolicyMap(policies []*conf_v1.Policy) map[string]*conf_v1.Policy {
	result := make(map[string]*conf_v1.Policy)

	for _, p := range policies {
		key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
		result[key] = p
	}

	return result
}

func (lbc *LoadBalancerController) getAllPolicies() []*conf_v1.Policy {
	var policies []*conf_v1.Policy

	for _, obj := range lbc.policyLister.List() {
		pol := obj.(*conf_v1.Policy)

		err := validation.ValidatePolicy(pol, lbc.isNginxPlus, lbc.enablePreviewPolicies)
		if err != nil {
			glog.V(3).Infof("Skipping invalid Policy %s/%s: %v", pol.Namespace, pol.Name, err)
			continue
		}

		policies = append(policies, pol)
	}

	return policies
}

func (lbc *LoadBalancerController) getPolicies(policies []conf_v1.PolicyReference, ownerNamespace string) ([]*conf_v1.Policy, []error) {
	var result []*conf_v1.Policy
	var errors []error

	for _, p := range policies {
		polNamespace := p.Namespace
		if polNamespace == "" {
			polNamespace = ownerNamespace
		}

		policyKey := fmt.Sprintf("%s/%s", polNamespace, p.Name)

		policyObj, exists, err := lbc.policyLister.GetByKey(policyKey)
		if err != nil {
			errors = append(errors, fmt.Errorf("Failed to get policy %s: %v", policyKey, err))
			continue
		}

		if !exists {
			errors = append(errors, fmt.Errorf("Policy %s doesn't exist", policyKey))
			continue
		}

		policy := policyObj.(*conf_v1.Policy)

		err = validation.ValidatePolicy(policy, lbc.isNginxPlus, lbc.enablePreviewPolicies)
		if err != nil {
			errors = append(errors, fmt.Errorf("Policy %s is invalid: %v", policyKey, err))
			continue
		}

		result = append(result, policy)
	}

	return result, errors
}

func (lbc *LoadBalancerController) addJWTSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.JWTAuth == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.JWTAuth.Secret)
		secretRef := lbc.secretStore.GetSecretReference(secretKey)

		secretRefs[secretKey] = secretRef

		if secretRef.Error != nil {
			return secretRef.Error
		}
	}

	return nil
}

func (lbc *LoadBalancerController) addIngressMTLSSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.IngressMTLS == nil {
			continue
		}

		secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.IngressMTLS.ClientCertSecret)
		secretRef := lbc.secretStore.GetSecretReference(secretKey)

		secretRefs[secretKey] = secretRef

		return secretRef.Error
	}

	return nil
}

func (lbc *LoadBalancerController) addEgressMTLSSecretRefs(secretRefs map[string]*secrets.SecretReference, policies []*conf_v1.Policy) error {
	for _, pol := range policies {
		if pol.Spec.EgressMTLS == nil {
			continue
		}
		if pol.Spec.EgressMTLS.TLSSecret != "" {
			secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.EgressMTLS.TLSSecret)
			secretRef := lbc.secretStore.GetSecretReference(secretKey)

			secretRefs[secretKey] = secretRef

			if secretRef.Error != nil {
				return secretRef.Error
			}
		}
		if pol.Spec.EgressMTLS.TrustedCertSecret != "" {
			secretKey := fmt.Sprintf("%v/%v", pol.Namespace, pol.Spec.EgressMTLS.TrustedCertSecret)
			secretRef := lbc.secretStore.GetSecretReference(secretKey)

			secretRefs[secretKey] = secretRef

			if secretRef.Error != nil {
				return secretRef.Error
			}
		}
	}

	return nil
}

func (lbc *LoadBalancerController) getPoliciesForSecret(secretNamespace string, secretName string) []*conf_v1.Policy {
	return findPoliciesForSecret(lbc.getAllPolicies(), secretNamespace, secretName)
}

func findPoliciesForSecret(policies []*conf_v1.Policy, secretNamespace string, secretName string) []*conf_v1.Policy {
	var res []*conf_v1.Policy

	for _, pol := range policies {
		if pol.Spec.IngressMTLS != nil && pol.Spec.IngressMTLS.ClientCertSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.JWTAuth != nil && pol.Spec.JWTAuth.Secret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.EgressMTLS != nil && pol.Spec.EgressMTLS.TLSSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		} else if pol.Spec.EgressMTLS != nil && pol.Spec.EgressMTLS.TrustedCertSecret == secretName && pol.Namespace == secretNamespace {
			res = append(res, pol)
		}
	}

	return res
}

func (lbc *LoadBalancerController) createTransportServer(transportServer *conf_v1alpha1.TransportServer) *configs.TransportServerEx {
	endpoints := make(map[string][]string)
	podsByIP := make(map[string]string)

	for _, u := range transportServer.Spec.Upstreams {
		podEndps, external, err := lbc.getEndpointsForUpstream(transportServer.Namespace, u.Service, uint16(u.Port))
		if err != nil {
			glog.Warningf("Error getting Endpoints for Upstream %v: %v", u.Name, err)
		}

		if external {
			glog.Warningf("ExternalName services are not yet supported in TransportServer upstreams")
		}

		// subselector is not supported yet in TransportServer upstreams. That's why we pass "nil" here
		endpointsKey := configs.GenerateEndpointsKey(transportServer.Namespace, u.Service, nil, uint16(u.Port))

		endps := getIPAddressesFromEndpoints(podEndps)
		endpoints[endpointsKey] = endps

		if lbc.isNginxPlus && lbc.isPrometheusEnabled {
			for _, endpoint := range podEndps {
				podsByIP[endpoint.Address] = endpoint.PodName
			}
		}
	}

	return &configs.TransportServerEx{
		TransportServer: transportServer,
		Endpoints:       endpoints,
		PodsByIP:        podsByIP,
	}
}

func (lbc *LoadBalancerController) getEndpointsForUpstream(namespace string, upstreamService string, upstreamPort uint16) (endps []podEndpoint, isExternal bool, err error) {
	svc, err := lbc.getServiceForUpstream(namespace, upstreamService, upstreamPort)
	if err != nil {
		return nil, false, fmt.Errorf("Error getting service %v: %v", upstreamService, err)
	}

	backend := &networking.IngressBackend{
		ServiceName: upstreamService,
		ServicePort: intstr.FromInt(int(upstreamPort)),
	}

	endps, isExternal, err = lbc.getEndpointsForIngressBackend(backend, svc)
	if err != nil {
		return nil, false, fmt.Errorf("Error retrieving endpoints for the service %v: %v", upstreamService, err)
	}

	return endps, isExternal, err
}

func (lbc *LoadBalancerController) getEndpointsForSubselector(namespace string, upstream conf_v1.Upstream) (endps []podEndpoint, err error) {
	svc, err := lbc.getServiceForUpstream(namespace, upstream.Service, upstream.Port)
	if err != nil {
		return nil, fmt.Errorf("Error getting service %v: %v", upstream.Service, err)
	}

	var targetPort int32

	for _, port := range svc.Spec.Ports {
		if port.Port == int32(upstream.Port) {
			targetPort, err = lbc.getTargetPort(&port, svc)
			if err != nil {
				return nil, fmt.Errorf("Error determining target port for port %v in service %v: %v", upstream.Port, svc.Name, err)
			}
			break
		}
	}

	if targetPort == 0 {
		return nil, fmt.Errorf("No port %v in service %s", upstream.Port, svc.Name)
	}

	endps, err = lbc.getEndpointsForServiceWithSubselector(targetPort, upstream.Subselector, svc)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving endpoints for the service %v: %v", upstream.Service, err)
	}

	return endps, err
}

func (lbc *LoadBalancerController) getEndpointsForServiceWithSubselector(targetPort int32, subselector map[string]string, svc *api_v1.Service) (endps []podEndpoint, err error) {
	pods, err := lbc.podLister.ListByNamespace(svc.Namespace, labels.Merge(svc.Spec.Selector, subselector).AsSelector())
	if err != nil {
		return nil, fmt.Errorf("Error getting pods in namespace %v that match the selector %v: %v", svc.Namespace, labels.Merge(svc.Spec.Selector, subselector), err)
	}

	svcEps, err := lbc.endpointLister.GetServiceEndpoints(svc)
	if err != nil {
		glog.V(3).Infof("Error getting endpoints for service %s from the cache: %v", svc.Name, err)
		return nil, err
	}

	endps = getEndpointsBySubselectedPods(targetPort, pods, svcEps)
	return endps, nil
}

func getEndpointsBySubselectedPods(targetPort int32, pods []*api_v1.Pod, svcEps api_v1.Endpoints) (endps []podEndpoint) {
	for _, pod := range pods {
		for _, subset := range svcEps.Subsets {
			for _, port := range subset.Ports {
				if port.Port != targetPort {
					continue
				}
				for _, address := range subset.Addresses {
					if address.IP == pod.Status.PodIP {
						addr := fmt.Sprintf("%v:%v", pod.Status.PodIP, targetPort)
						ownerType, ownerName := getPodOwnerTypeAndName(pod)
						podEnd := podEndpoint{
							Address: addr,
							PodName: getPodName(address.TargetRef),
							MeshPodOwner: configs.MeshPodOwner{
								OwnerType: ownerType,
								OwnerName: ownerName,
							},
						}
						endps = append(endps, podEnd)
					}
				}
			}
		}
	}
	return endps
}

func getPodName(pod *api_v1.ObjectReference) string {
	if pod != nil {
		return pod.Name
	}
	return ""
}

func (lbc *LoadBalancerController) getHealthChecksForIngressBackend(backend *networking.IngressBackend, namespace string) *api_v1.Probe {
	svc, err := lbc.getServiceForIngressBackend(backend, namespace)
	if err != nil {
		glog.V(3).Infof("Error getting service %v: %v", backend.ServiceName, err)
		return nil
	}
	svcPort := lbc.getServicePortForIngressPort(backend.ServicePort, svc)
	if svcPort == nil {
		return nil
	}
	pods, err := lbc.podLister.ListByNamespace(svc.Namespace, labels.Set(svc.Spec.Selector).AsSelector())
	if err != nil {
		glog.V(3).Infof("Error fetching pods for namespace %v: %v", svc.Namespace, err)
		return nil
	}
	return findProbeForPods(pods, svcPort)
}

func findProbeForPods(pods []*api_v1.Pod, svcPort *api_v1.ServicePort) *api_v1.Probe {
	if len(pods) > 0 {
		pod := pods[0]
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if compareContainerPortAndServicePort(port, *svcPort) {
					// only http ReadinessProbes are useful for us
					if container.ReadinessProbe != nil && container.ReadinessProbe.Handler.HTTPGet != nil && container.ReadinessProbe.PeriodSeconds > 0 {
						return container.ReadinessProbe
					}
				}
			}
		}
	}
	return nil
}

func compareContainerPortAndServicePort(containerPort api_v1.ContainerPort, svcPort api_v1.ServicePort) bool {
	targetPort := svcPort.TargetPort
	if (targetPort == intstr.IntOrString{}) {
		return svcPort.Port > 0 && svcPort.Port == containerPort.ContainerPort
	}
	switch targetPort.Type {
	case intstr.String:
		return targetPort.StrVal == containerPort.Name && svcPort.Protocol == containerPort.Protocol
	case intstr.Int:
		return targetPort.IntVal > 0 && targetPort.IntVal == containerPort.ContainerPort
	}
	return false
}

func (lbc *LoadBalancerController) getExternalEndpointsForIngressBackend(backend *networking.IngressBackend, svc *api_v1.Service) []podEndpoint {
	address := fmt.Sprintf("%s:%d", svc.Spec.ExternalName, int32(backend.ServicePort.IntValue()))
	endpoints := []podEndpoint{
		{
			Address: address,
			PodName: "",
		},
	}
	return endpoints
}

func (lbc *LoadBalancerController) getEndpointsForIngressBackend(backend *networking.IngressBackend, svc *api_v1.Service) (result []podEndpoint, isExternal bool, err error) {
	endps, err := lbc.endpointLister.GetServiceEndpoints(svc)
	if err != nil {
		if svc.Spec.Type == api_v1.ServiceTypeExternalName {
			if !lbc.isNginxPlus {
				return nil, false, fmt.Errorf("Type ExternalName Services feature is only available in NGINX Plus")
			}
			result = lbc.getExternalEndpointsForIngressBackend(backend, svc)
			return result, true, nil
		}
		glog.V(3).Infof("Error getting endpoints for service %s from the cache: %v", svc.Name, err)
		return nil, false, err
	}

	result, err = lbc.getEndpointsForPort(endps, backend.ServicePort, svc)
	if err != nil {
		glog.V(3).Infof("Error getting endpoints for service %s port %v: %v", svc.Name, backend.ServicePort, err)
		return nil, false, err
	}
	return result, false, nil
}

func (lbc *LoadBalancerController) getEndpointsForPort(endps api_v1.Endpoints, ingSvcPort intstr.IntOrString, svc *api_v1.Service) ([]podEndpoint, error) {
	var targetPort int32
	var err error

	for _, port := range svc.Spec.Ports {
		if (ingSvcPort.Type == intstr.Int && port.Port == int32(ingSvcPort.IntValue())) || (ingSvcPort.Type == intstr.String && port.Name == ingSvcPort.String()) {
			targetPort, err = lbc.getTargetPort(&port, svc)
			if err != nil {
				return nil, fmt.Errorf("Error determining target port for port %v in Ingress: %v", ingSvcPort, err)
			}
			break
		}
	}

	if targetPort == 0 {
		return nil, fmt.Errorf("No port %v in service %s", ingSvcPort, svc.Name)
	}

	for _, subset := range endps.Subsets {
		for _, port := range subset.Ports {
			if port.Port == targetPort {
				var endpoints []podEndpoint
				for _, address := range subset.Addresses {
					addr := fmt.Sprintf("%v:%v", address.IP, port.Port)
					podEnd := podEndpoint{
						Address: addr,
					}
					if address.TargetRef != nil {
						parentType, parentName := lbc.getPodOwnerTypeAndNameFromAddress(address.TargetRef.Namespace, address.TargetRef.Name)
						podEnd.OwnerType = parentType
						podEnd.OwnerName = parentName
						podEnd.PodName = address.TargetRef.Name
					}
					endpoints = append(endpoints, podEnd)
				}
				return endpoints, nil
			}
		}
	}

	return nil, fmt.Errorf("No endpoints for target port %v in service %s", targetPort, svc.Name)
}

func (lbc *LoadBalancerController) getPodOwnerTypeAndNameFromAddress(ns, name string) (parentType, parentName string) {
	obj, exists, err := lbc.podLister.GetByKey(fmt.Sprintf("%s/%s", ns, name))
	if err != nil {
		glog.Warningf("could not get pod by key %s/%s: %v", ns, name, err)
		return "", ""
	}
	if exists {
		pod := obj.(*api_v1.Pod)
		return getPodOwnerTypeAndName(pod)
	}
	return "", ""
}

func getPodOwnerTypeAndName(pod *api_v1.Pod) (parentType, parentName string) {
	parentType = "deployment"
	for _, owner := range pod.GetOwnerReferences() {
		parentName = owner.Name
		if owner.Controller != nil && *owner.Controller {
			if owner.Kind == "StatefulSet" || owner.Kind == "DaemonSet" {
				parentType = strings.ToLower(owner.Kind)
			}
			if owner.Kind == "ReplicaSet" && strings.HasSuffix(owner.Name, pod.Labels["pod-template-hash"]) {
				parentName = strings.TrimSuffix(owner.Name, "-"+pod.Labels["pod-template-hash"])
			}
		}
	}
	return parentType, parentName
}

func (lbc *LoadBalancerController) getServicePortForIngressPort(ingSvcPort intstr.IntOrString, svc *api_v1.Service) *api_v1.ServicePort {
	for _, port := range svc.Spec.Ports {
		if (ingSvcPort.Type == intstr.Int && port.Port == int32(ingSvcPort.IntValue())) || (ingSvcPort.Type == intstr.String && port.Name == ingSvcPort.String()) {
			return &port
		}
	}
	return nil
}

func (lbc *LoadBalancerController) getTargetPort(svcPort *api_v1.ServicePort, svc *api_v1.Service) (int32, error) {
	if (svcPort.TargetPort == intstr.IntOrString{}) {
		return svcPort.Port, nil
	}

	if svcPort.TargetPort.Type == intstr.Int {
		return int32(svcPort.TargetPort.IntValue()), nil
	}

	pods, err := lbc.podLister.ListByNamespace(svc.Namespace, labels.Set(svc.Spec.Selector).AsSelector())
	if err != nil {
		return 0, fmt.Errorf("Error getting pod information: %v", err)
	}

	if len(pods) == 0 {
		return 0, fmt.Errorf("No pods of service %s", svc.Name)
	}

	pod := pods[0]

	portNum, err := findPort(pod, svcPort)
	if err != nil {
		return 0, fmt.Errorf("Error finding named port %v in pod %s: %v", svcPort, pod.Name, err)
	}

	return portNum, nil
}

func (lbc *LoadBalancerController) getServiceForUpstream(namespace string, upstreamService string, upstreamPort uint16) (*api_v1.Service, error) {
	backend := &networking.IngressBackend{
		ServiceName: upstreamService,
		ServicePort: intstr.FromInt(int(upstreamPort)),
	}
	return lbc.getServiceForIngressBackend(backend, namespace)
}

func (lbc *LoadBalancerController) getServiceForIngressBackend(backend *networking.IngressBackend, namespace string) (*api_v1.Service, error) {
	svcKey := namespace + "/" + backend.ServiceName
	svcObj, svcExists, err := lbc.svcLister.GetByKey(svcKey)
	if err != nil {
		return nil, err
	}

	if svcExists {
		return svcObj.(*api_v1.Service), nil
	}

	return nil, fmt.Errorf("service %s doesn't exist", svcKey)
}

// HasCorrectIngressClass checks if resource ingress class annotation (if exists) or ingressClass string for VS/VSR is matching with ingress controller class
func (lbc *LoadBalancerController) HasCorrectIngressClass(obj interface{}) bool {
	var class string
	var isIngress bool
	switch obj := obj.(type) {
	case *conf_v1.VirtualServer:
		class = obj.Spec.IngressClass
	case *conf_v1.VirtualServerRoute:
		class = obj.Spec.IngressClass
	case *networking.Ingress:
		isIngress = true
		class = obj.Annotations[ingressClassKey]
		if class == "" && obj.Spec.IngressClassName != nil {
			class = *obj.Spec.IngressClassName
		} else {
			// the annotation takes precedence over the field
			glog.Warningln("Using the DEPRECATED annotation 'kubernetes.io/ingress.class'. The 'ingressClassName' field will be ignored.")
		}

	default:
		return false
	}

	// useIngressClassOnly only applies for Ingress resources
	if lbc.useIngressClassOnly && isIngress {
		return class == lbc.ingressClass
	}
	return class == lbc.ingressClass || class == ""
}

// isHealthCheckEnabled checks if health checks are enabled so we can only query pods if enabled.
func (lbc *LoadBalancerController) isHealthCheckEnabled(ing *networking.Ingress) bool {
	if healthCheckEnabled, exists, err := configs.GetMapKeyAsBool(ing.Annotations, "nginx.com/health-checks", ing); exists {
		if err != nil {
			glog.Error(err)
		}
		return healthCheckEnabled
	}
	return false
}

// getMinionsForHost returns a list of all minion ingress resources for a given master

func formatWarningMessages(w []string) string {
	return strings.Join(w, "; ")
}

func (lbc *LoadBalancerController) syncSVIDRotation(svidResponse *workload.X509SVIDs) {
	lbc.syncLock.Lock()
	defer lbc.syncLock.Unlock()
	glog.V(3).Info("Rotating SPIFFE Certificates")
	err := lbc.configurator.AddOrUpdateSpiffeCerts(svidResponse)
	if err != nil {
		glog.Errorf("failed to rotate SPIFFE certificates: %v", err)
	}
}

func (lbc *LoadBalancerController) syncAppProtectPolicy(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectPolicy %v", key)
	obj, polExists, err := lbc.appProtectPolicyLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []AppProtectChange
	var problems []AppProtectProblem

	if !polExists {
		glog.V(2).Infof("Deleting AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeletePolicy(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectPolicy: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdatePolicy(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)

}

func (lbc *LoadBalancerController) syncAppProtectLogConf(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectLogConf %v", key)
	obj, confExists, err := lbc.appProtectLogConfLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var changes []AppProtectChange
	var problems []AppProtectProblem

	if !confExists {
		glog.V(2).Infof("Deleting AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.DeleteLogConf(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectLogConf: %v\n", key)

		changes, problems = lbc.appProtectConfiguration.AddOrUpdateLogConf(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectChanges(changes)
	lbc.processAppProtectProblems(problems)

}

func (lbc *LoadBalancerController) syncAppProtectUserSig(task task) {
	key := task.Key
	glog.V(3).Infof("Syncing AppProtectUserSig %v", key)
	obj, sigExists, err := lbc.appProtectUserSigLister.GetByKey(key)
	if err != nil {
		lbc.syncQueue.Requeue(task, err)
		return
	}

	var change AppProtectUserSigChange
	var problems []AppProtectProblem

	if !sigExists {
		glog.V(2).Infof("Deleting AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.DeleteUserSig(key)
	} else {
		glog.V(2).Infof("Adding or Updating AppProtectUserSig: %v\n", key)

		change, problems = lbc.appProtectConfiguration.AddOrUpdateUserSig(obj.(*unstructured.Unstructured))
	}

	lbc.processAppProtectUserSigChange(change)
	lbc.processAppProtectProblems(problems)
}

// IsNginxReady returns ready status of NGINX
func (lbc *LoadBalancerController) IsNginxReady() bool {
	return lbc.isNginxReady
}

func (lbc *LoadBalancerController) addInternalRouteServer() {
	if lbc.internalRoutesEnabled {
		if err := lbc.configurator.AddInternalRouteConfig(); err != nil {
			glog.Warningf("failed to configure internal route server: %v", err)
		}
	}
}
