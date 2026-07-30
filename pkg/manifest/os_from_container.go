package manifest

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/customizations/fsnode"
	"github.com/osbuild/image-builder/pkg/customizations/subscription"
	"github.com/osbuild/image-builder/pkg/osbuild"
	"github.com/osbuild/image-builder/pkg/shutil"
)

const (
	// anacondaPostScriptsDir is the directory Anaconda unconditionally reads
	// drop-in %post scripts from, whether or not the user supplied a
	// kickstart of their own.
	anacondaPostScriptsDir = "/usr/share/anaconda/post-scripts"

	// anacondaSubscriptionPostScript is our drop-in. The numeric prefix
	// orders it against any scripts the container ships (Anaconda sorts the
	// directory before concatenating).
	anacondaSubscriptionPostScript = anacondaPostScriptsDir + "/50-osbuild-subscription.ks"

	// anacondaSystemRoot is where Anaconda mounts the system being
	// installed. It is the `system_root` default from anaconda.conf, which a
	// chrooted %post runs in and a %post --nochroot sees at this path.
	anacondaSystemRoot = "/mnt/sysroot"

	// subscriptionEtcUnitDir is where osbuild's
	// org.osbuild.systemd.unit.create stage writes a system unit when it is
	// configured with unit-path "etc".
	subscriptionEtcUnitDir = "/etc/systemd/system"
)

// OSFromContainer represents a pipeline that deploys an OS tree from a container.
type OSFromContainer struct {
	Base

	SourceContainer *container.SourceSpec

	// PayloadContainer is an optional container to embed in the image's
	// container storage (e.g., for bootc installer ISOs that need the
	// payload container available at install time).
	PayloadContainer *container.SourceSpec

	// Subscription, when set, places registration credentials in this tree
	// together with an Anaconda drop-in %post script that installs them onto
	// the system being installed. Only meaningful when this tree is an
	// installer environment running Anaconda.
	Subscription *subscription.ImageOptions

	sourceContainerSpec  *container.Spec
	payloadContainerSpec *container.Spec

	inlineData []string
}

var _ Pipeline = (*OSFromContainer)(nil)

func NewOSFromContainer(name string, build Build, srcContainer *container.SourceSpec) *OSFromContainer {
	p := &OSFromContainer{
		Base:            NewBase(name, build),
		SourceContainer: srcContainer,
	}
	build.addDependent(p)
	return p
}

func (p *OSFromContainer) getContainerSources() []container.SourceSpec {
	sources := []container.SourceSpec{*p.SourceContainer}
	if p.PayloadContainer != nil {
		sources = append(sources, *p.PayloadContainer)
	}
	return sources
}

func (p *OSFromContainer) getContainerSpecs() []container.Spec {
	specs := []container.Spec{*p.sourceContainerSpec}
	if p.payloadContainerSpec != nil {
		specs = append(specs, *p.payloadContainerSpec)
	}
	return specs
}

func (p *OSFromContainer) serializeStart(inputs Inputs) error {
	if p.sourceContainerSpec != nil {
		return errors.New("OSFromContainer: double call to serializeStart()")
	}
	expectedContainers := 1
	if p.PayloadContainer != nil {
		expectedContainers = 2
	}
	if len(inputs.Containers) < 1 {
		return errors.New("OSFromContainer: no container in inputs")
	}
	if len(inputs.Containers) != expectedContainers {
		return fmt.Errorf("OSFromContainer: expected %d containers in inputs, got %d", expectedContainers, len(inputs.Containers))
	}
	// The first container is the source container for deployment
	p.sourceContainerSpec = &inputs.Containers[0]
	// The second container (if present) is the payload container to embed in storage
	if len(inputs.Containers) > 1 {
		p.payloadContainerSpec = &inputs.Containers[1]
	}
	return nil
}

func (p *OSFromContainer) serializeEnd() {
	p.sourceContainerSpec = nil
	p.payloadContainerSpec = nil
	p.inlineData = nil
}

func (p *OSFromContainer) serialize() (osbuild.Pipeline, error) {
	if p.sourceContainerSpec == nil {
		return osbuild.Pipeline{}, fmt.Errorf("OSFromContainer: serialization not started")
	}

	pipeline, err := p.Base.serialize()
	if err != nil {
		return osbuild.Pipeline{}, err
	}

	image := osbuild.NewContainersInputForSingleSource(*p.sourceContainerSpec)
	stage, err := osbuild.NewContainerDeployStage(image, &osbuild.ContainerDeployOptions{RemoveSignatures: true})
	if err != nil {
		return pipeline, err
	}
	pipeline.AddStage(stage)

	// Embed payload container in container storage
	if p.payloadContainerSpec != nil {
		for _, stage := range osbuild.GenContainerStorageStages("", []container.Spec{*p.payloadContainerSpec}) {
			pipeline.AddStage(stage)
		}
	}

	if p.Subscription != nil {
		stages, err := p.subscriptionStages()
		if err != nil {
			return osbuild.Pipeline{}, err
		}
		pipeline.AddStages(stages...)
	}

	return pipeline, nil
}

// subscriptionStages creates the registration credentials and unit in this
// tree, plus an Anaconda drop-in %post script that copies them onto the
// system being installed and enables the service there.
//
// The drop-in is the only hook available for a generic bootc installer ISO:
// the container brings its own Anaconda configuration and kickstart, so there
// is no kickstart of ours to append a %post to. Anaconda loads every %post it
// finds in anacondaPostScriptsDir regardless, even when no kickstart is
// supplied at all.
//
// Note that the service is deliberately *not* enabled in this tree. Unlike the
// bootc disk image, where the tree is the installed system, here it is the
// ephemeral installer environment; enabling it would make the installer try to
// register itself. An un-enabled unit is inert.
func (p *OSFromContainer) subscriptionStages() ([]*osbuild.Stage, error) {
	subStage, subDirs, subFiles, _, err := subscriptionService(*p.Subscription, &subscriptionServiceOptions{
		InsightsOnBoot: true,
		UnitPath:       osbuild.EtcUnitPath,
	})
	if err != nil {
		return nil, err
	}

	// Derive the %post from what was actually created rather than restating
	// it: which files subscriptionService() emits depends on the options (the
	// insights drop-in is conditional), so a hand-written list would drift.
	copyPaths := []string{path.Join(subscriptionEtcUnitDir, subscriptionServiceFilename)}
	for _, file := range subFiles {
		copyPaths = append(copyPaths, file.Path())
	}
	slices.Sort(copyPaths)

	mkdirPaths := make([]string, 0, len(subDirs)+len(copyPaths))
	for _, dir := range subDirs {
		mkdirPaths = append(mkdirPaths, dir.Path())
	}
	for _, copyPath := range copyPaths {
		mkdirPaths = append(mkdirPaths, path.Dir(copyPath))
	}
	slices.Sort(mkdirPaths)
	mkdirPaths = slices.Compact(mkdirPaths)

	postScript, err := fsnode.NewFile(
		anacondaSubscriptionPostScript, nil, nil, nil,
		[]byte(subscriptionPostScript(mkdirPaths, copyPaths)),
	)
	if err != nil {
		return nil, err
	}

	postScriptDir, err := fsnode.NewDirectory(anacondaPostScriptsDir, nil, nil, nil, true)
	if err != nil {
		return nil, err
	}

	dirs := make([]*fsnode.Directory, 0, len(subDirs)+1)
	dirs = append(dirs, subDirs...)
	dirs = append(dirs, postScriptDir)

	files := make([]*fsnode.File, 0, len(subFiles)+1)
	files = append(files, subFiles...)
	files = append(files, postScript)

	fileStages, err := p.genFileStagesAndRecordInlineData(files)
	if err != nil {
		return nil, err
	}

	stages := []*osbuild.Stage{subStage}
	stages = append(stages, osbuild.GenDirectoryNodesStages(dirs)...)
	stages = append(stages, fileStages...)
	return stages, nil
}

// subscriptionPostScript renders the Anaconda drop-in. The first section runs
// outside the chroot so it can read this (the installer's) filesystem; the
// second runs inside the installed system to enable the unit.
//
// Both use --erroronfail: a broken ferry aborts the install rather than
// leaving the user with a system that silently never registers.
func subscriptionPostScript(mkdirPaths, copyPaths []string) string {
	var b strings.Builder

	b.WriteString("# Created by image-builder.\n")
	b.WriteString("# Installs subscription credentials onto the target system so that it\n")
	b.WriteString("# registers on first boot.\n\n")

	b.WriteString("%post --nochroot --erroronfail\n")
	for _, dir := range mkdirPaths {
		fmt.Fprintf(&b, "mkdir -p %s\n", shutil.Quote(path.Join(anacondaSystemRoot, dir)))
	}
	for _, src := range copyPaths {
		fmt.Fprintf(&b, "cp -a %s %s\n", shutil.Quote(src), shutil.Quote(path.Join(anacondaSystemRoot, src)))
	}
	// The key file is world-readable until the service removes it on first
	// boot; it holds the activation key, so tighten it on the way in.
	fmt.Fprintf(&b, "chmod 0600 %s\n", shutil.Quote(path.Join(anacondaSystemRoot, subscriptionKeyFilepath)))
	b.WriteString("%end\n\n")

	b.WriteString("%post --erroronfail\n")
	fmt.Fprintf(&b, "systemctl enable %s\n", shutil.Quote(subscriptionServiceFilename))
	b.WriteString("%end\n")

	return b.String()
}

// genFileStagesAndRecordInlineData returns the stages that create the given
// files and records their contents as inline sources for the manifest.
func (p *OSFromContainer) genFileStagesAndRecordInlineData(files []*fsnode.File) ([]*osbuild.Stage, error) {
	for _, file := range files {
		// files that come via an URI are not inline data, they would need to
		// be added to the manifest sources via a fileRefs() implementation
		// like the one in the OS pipeline
		if file.URI() != "" {
			return nil, fmt.Errorf("cannot create file %q from %q: files from an URI are not supported here", file.Path(), file.URI())
		}
		p.inlineData = append(p.inlineData, string(file.Data()))
	}

	return osbuild.GenFileNodesStages(files), nil
}

func (p *OSFromContainer) getInline() []string {
	return p.inlineData
}
