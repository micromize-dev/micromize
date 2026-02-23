// Copyright 2022-2025 The Inspektor Gadget authors
// Copyright 2025 The micromize authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package localmanager is a simplified fork of the IG localmanager operator,
// stripped down to only support containerd and container-scoped tracing.
// It adds the ability to inject extra ContainerCollectionOptions (e.g. WithPubSub)
// so that micromize can hook into container lifecycle events on the same
// ContainerCollection the operator uses for gadget lifecycle.
package localmanager

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	operatorName         = "LocalManager"
	dockerSocketPath     = "docker-socketpath"
	containerdSocketPath = "containerd-socketpath"
)

type mountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

// ContainerCollectionOption is an alias for the IG container collection option type.
type ContainerCollectionOption = containercollection.ContainerCollectionOption

// LocalManager is a simplified fork of the upstream localmanager operator.
// It only supports containerd and container-scoped tracing (no host mode).
type LocalManager struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	extraCCOpts         []ContainerCollectionOption
}

// New creates a new LocalManager with optional extra ContainerCollectionOptions.
func New(extraOpts ...ContainerCollectionOption) *LocalManager {
	return &LocalManager{extraCCOpts: extraOpts}
}

// ContainerCollection returns the initialized ContainerCollection.
func (l *LocalManager) ContainerCollection() *containercollection.ContainerCollection {
	return l.containerCollection
}

func (l *LocalManager) Name() string {
	return operatorName
}

func (l *LocalManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers"
}

func (l *LocalManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          dockerSocketPath,
			DefaultValue: runtimeclient.DockerDefaultSocketPath,
			Description:  "Docker Engine API Unix socket path",
		},
		{
			Key:          containerdSocketPath,
			DefaultValue: runtimeclient.ContainerdDefaultSocketPath,
			Description:  "Containerd CRI Unix socket path",
		},
	}
}

func (l *LocalManager) ParamDescs() params.ParamDescs {
	return common.GetContainerSelectorParams(false)
}

func (l *LocalManager) Init(operatorParams *params.Params) error {
	type runtimeDef struct {
		name    types.RuntimeName
		paramKey string
	}

	runtimes := []runtimeDef{
		{types.RuntimeNameDocker, dockerSocketPath},
		{types.RuntimeNameContainerd, containerdSocketPath},
	}

	var rc []*containerutilsTypes.RuntimeConfig
	for _, rt := range runtimes {
		socketPath := operatorParams.Get(rt.paramKey).AsString()

		cleanSocketPath, err := securejoin.SecureJoin(host.HostRoot, socketPath)
		if err != nil {
			log.Debugf("securejoin failed for %s: %s", rt.name, err)
			continue
		}

		if _, err := os.Stat(cleanSocketPath); err != nil {
			log.Debugf("Ignoring runtime %q with non-existent socket %q", rt.name, socketPath)
			continue
		}

		rc = append(rc, &containerutilsTypes.RuntimeConfig{
			Name:            rt.name,
			SocketPath:      cleanSocketPath,
			RuntimeProtocol: "internal",
		})
	}

	if err := l.initCollections(rc); err != nil {
		log.Warnf("Failed to create container-collection")
		log.Debugf("Failed to create container-collection: %s", err)
	}

	return nil
}

func (l *LocalManager) initCollections(rc []*containerutilsTypes.RuntimeConfig) error {
	var cc containercollection.ContainerCollection

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	var err error
	l.tracerCollection, err = tracercollection.NewTracerCollection(&cc)
	if err != nil {
		return fmt.Errorf("creating tracer collection: %w", err)
	}

	ccOpts := []containercollection.ContainerCollectionOption{}

	// Inject extra options (e.g. WithPubSub) before the standard options.
	ccOpts = append(ccOpts, l.extraCCOpts...)

	ccOpts = append(ccOpts,
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(rc),
		containercollection.WithOCIConfigForInitialContainer(),
		containercollection.WithContainerFanotifyEbpf(),
		containercollection.WithTracerCollection(l.tracerCollection),
		containercollection.WithProcEnrichment(),
	)

	if err := cc.Initialize(ccOpts...); err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	l.containerCollection = &cc
	return nil
}

func (l *LocalManager) Close() error {
	if l.containerCollection != nil {
		l.containerCollection.Close()
	}
	if l.tracerCollection != nil {
		l.tracerCollection.Close()
	}
	return nil
}

// --- Operator instance types for gadget lifecycle ---

type localManagerTrace struct {
	manager         *LocalManager
	mountnsmap      *ebpf.Map
	subscriptionKey string

	attachedContainers map[*containercollection.Container]struct{}
	attacher           attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext

	eventWrappers       map[datasource.DataSource]*compat.EventWrapperBase
	containersPublisher *common.ContainersPublisher
}

func (l *localManagerTrace) Name() string {
	return operatorName
}

func (l *localManagerTrace) PreGadgetRun() error {
	if l.gadgetInstance == nil {
		return nil
	}
	return l.handleGadgetInstance(l.gadgetCtx.Logger())
}

func (l *localManagerTrace) handleGadgetInstance(log logger.Logger) error {
	id := uuid.New()
	containerSelector := common.NewContainerSelector(l.params)

	if setter, ok := l.gadgetInstance.(mountNsMapSetter); ok {
		if l.manager.containerCollection == nil {
			return fmt.Errorf("container-collection isn't available")
		}

		id := id.String()
		if err := l.manager.tracerCollection.AddTracer(id, containerSelector); err != nil {
			return fmt.Errorf("adding tracer %q: %w", id, err)
		}

		mountnsmap, err := l.manager.tracerCollection.TracerMountNsMap(id)
		if err != nil {
			l.manager.tracerCollection.RemoveTracer(id)
			return fmt.Errorf("getting mount namespace map for tracer %q: %w", id, err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)
		l.mountnsmap = mountnsmap
	}

	if att, ok := l.gadgetInstance.(attacher); ok {
		if l.manager.containerCollection == nil {
			return fmt.Errorf("container-collection isn't available")
		}

		l.attacher = att
		var containers []*containercollection.Container

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			if err := att.AttachContainer(container); err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					l.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", container.K8s.ContainerName, ve)
				}
				log.Warnf("start tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}

			l.attachedContainers[container] = struct{}{}
			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.DetachContainer()")
			if err := att.DetachContainer(container); err != nil {
				log.Warnf("stop tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		l.subscriptionKey = id.String()
		log.Debugf("add subscription to containerCollection")
		containers = l.manager.containerCollection.Subscribe(
			l.subscriptionKey,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				log.Debugf("%s: %s", event.Type.String(), event.Container.Runtime.ContainerID)
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					attachContainerFunc(event.Container)
				case containercollection.EventTypeRemoveContainer:
					detachContainerFunc(event.Container)
				case containercollection.EventTypePreCreateContainer:
					// nothing to do
				default:
					log.Errorf("unknown event type, expected either %s, %s or %s, got %s",
						containercollection.EventTypePreCreateContainer,
						containercollection.EventTypeAddContainer,
						containercollection.EventTypeRemoveContainer,
						event.Type)
				}
			},
		)

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}
	return nil
}

func (l *localManagerTrace) PostGadgetRun() error {
	if l.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		l.manager.tracerCollection.RemoveTracer(l.subscriptionKey)
	}
	if l.subscriptionKey != "" {
		log.Debugf("calling Unsubscribe()")
		l.manager.containerCollection.Unsubscribe(l.subscriptionKey)

		if l.attacher != nil {
			for container := range l.attachedContainers {
				l.attacher.DetachContainer(container)
			}
		}
	}
	return nil
}

type localManagerTraceWrapper struct {
	localManagerTrace
}

func (l *LocalManager) GlobalParams() api.Params {
	return apihelpers.ParamDescsToParams(l.GlobalParamDescs())
}

func (l *LocalManager) InstanceParams() api.Params {
	return apihelpers.ParamDescsToParams(l.ParamDescs())
}

func (l *LocalManager) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	params := l.ParamDescs().ToParams()
	if err := params.CopyFromMap(paramValues, ""); err != nil {
		return nil, err
	}

	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}

	var containersPublisher *common.ContainersPublisher
	if v.GetBool("annotations.enable-containers-datasource") {
		if l.containerCollection == nil {
			return nil, fmt.Errorf("container-collection isn't available, but containers datasource is enabled")
		}
		var err error
		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, l.containerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating containers publisher: %w", err)
		}
	}

	traceInstance := &localManagerTraceWrapper{
		localManagerTrace: localManagerTrace{
			manager:             l,
			attachedContainers:  make(map[*containercollection.Container]struct{}),
			params:              params,
			gadgetCtx:           gadgetCtx,
			eventWrappers:       make(map[datasource.DataSource]*compat.EventWrapperBase),
			containersPublisher: containersPublisher,
		},
	}

	activate := false

	if t, ok := gadgetCtx.GetVar(gadgets.MntNsFilterMapName); ok {
		if _, ok := t.(*ebpf.Map); ok {
			gadgetCtx.Logger().Debugf("gadget requested map %s", gadgets.MntNsFilterMapName)
			activate = true
		}
	}

	if val, ok := gadgetCtx.GetVar("NeedContainerEvents"); ok {
		if b, ok := val.(bool); ok && b {
			activate = true
		}
	}

	wrappers, err := compat.GetEventWrappers(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("getting event wrappers: %w", err)
	}
	traceInstance.eventWrappers = wrappers
	if len(wrappers) > 0 {
		activate = true
	}

	if !activate {
		return nil, nil
	}

	return traceInstance, nil
}

func (l *localManagerTrace) ParamDescs() params.ParamDescs {
	return common.GetContainerSelectorParams(false)
}

func (l *LocalManager) Priority() int {
	return -1
}

func (l *localManagerTraceWrapper) PreStart(gadgetCtx operators.GadgetContext) error {
	l.gadgetInstance, _ = gadgetCtx.GetVar("ebpfInstance")

	if l.manager.containerCollection != nil {
		compat.Subscribe(
			l.eventWrappers,
			l.manager.containerCollection.EnrichEventByMntNs,
			l.manager.containerCollection.EnrichEventByNetNs,
			0,
		)
	}

	containerSelector := common.NewContainerSelector(l.params)

	if l.manager.containerCollection == nil {
		return fmt.Errorf("container-collection isn't available")
	}

	id := uuid.New().String()
	if err := l.manager.tracerCollection.AddTracer(id, containerSelector); err != nil {
		return fmt.Errorf("adding tracer %q: %w", id, err)
	}

	mountnsmap, err := l.manager.tracerCollection.TracerMountNsMap(id)
	if err != nil {
		l.manager.tracerCollection.RemoveTracer(id)
		return fmt.Errorf("getting mount namespace map for tracer %q: %w", id, err)
	}

	gadgetCtx.Logger().Debugf("set mountnsmap for gadget")
	gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)
	gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)
	l.mountnsmap = mountnsmap

	return l.PreGadgetRun()
}

func (l *localManagerTraceWrapper) Start(gadgetCtx operators.GadgetContext) error {
	if l.containersPublisher == nil {
		return nil
	}

	containerSelector := common.NewContainerSelector(l.params)
	return l.containersPublisher.PublishContainers(false, nil, containerSelector)
}

func (l *localManagerTraceWrapper) Stop(gadgetCtx operators.GadgetContext) error {
	if l.containersPublisher != nil {
		l.containersPublisher.Unsubscribe()
	}
	return nil
}

func (l *localManagerTraceWrapper) Close(gadgetCtx operators.GadgetContext) error {
	return l.PostGadgetRun()
}


