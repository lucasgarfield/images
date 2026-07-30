package manifest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder/pkg/customizations/subscription"
	"github.com/osbuild/image-builder/pkg/osbuild"
)

// postScriptFrom returns the Anaconda drop-in that subscriptionStages()
// recorded as inline data.
func postScriptFrom(t *testing.T, p *OSFromContainer) string {
	t.Helper()

	var found []string
	for _, data := range p.inlineData {
		if strings.Contains(data, "%post") {
			found = append(found, data)
		}
	}
	require.Len(t, found, 1, "expected exactly one inline %%post script")
	return found[0]
}

func TestOSFromContainerSubscriptionStages(t *testing.T) {
	p := &OSFromContainer{
		Subscription: &subscription.ImageOptions{
			Organization:  "theorg",
			ActivationKey: "thekey",
			BaseUrl:       "https://example.com/baseurl",
		},
	}

	stages, err := p.subscriptionStages()
	require.NoError(t, err)

	var stageTypes []string
	for _, stage := range stages {
		stageTypes = append(stageTypes, stage.Type)
	}

	// the registration unit and the files (credentials + drop-in) are created
	assert.Contains(t, stageTypes, "org.osbuild.systemd.unit.create")
	assert.Contains(t, stageTypes, "org.osbuild.mkdir")
	assert.Contains(t, stageTypes, "org.osbuild.copy")

	// The service must NOT be enabled in this tree: it is the ephemeral
	// installer environment, not the system being installed. Enabling it here
	// would make the installer register itself.
	assert.NotContains(t, stageTypes, "org.osbuild.systemd")
}

func TestOSFromContainerSubscriptionPostScript(t *testing.T) {
	type testCase struct {
		subOpts     subscription.ImageOptions
		expected    []string
		notExpected []string
	}

	testCases := map[string]testCase{
		"simple": {
			subOpts: subscription.ImageOptions{
				Organization:  "theorg",
				ActivationKey: "thekey",
				BaseUrl:       "https://example.com/baseurl",
			},
			expected: []string{
				"%post --nochroot --erroronfail",
				"mkdir -p '/mnt/sysroot/etc/systemd/system'",
				"cp -a '/etc/osbuild-subscription-register.env' '/mnt/sysroot/etc/osbuild-subscription-register.env'",
				"cp -a '/etc/systemd/system/osbuild-subscription-register.service' '/mnt/sysroot/etc/systemd/system/osbuild-subscription-register.service'",
				"chmod 0600 '/mnt/sysroot/etc/osbuild-subscription-register.env'",
				"%post --erroronfail",
				"systemctl enable 'osbuild-subscription-register.service'",
			},
			notExpected: []string{
				"insights-client-boot.service.d",
			},
		},
		// the insights drop-in is conditional, so the ferry must pick it up
		// without the file list being restated by hand
		"insights": {
			subOpts: subscription.ImageOptions{
				Organization:  "theorg",
				ActivationKey: "thekey",
				BaseUrl:       "https://example.com/baseurl",
				Insights:      true,
			},
			expected: []string{
				"mkdir -p '/mnt/sysroot/etc/systemd/system/insights-client-boot.service.d'",
				"cp -a '/etc/systemd/system/insights-client-boot.service.d/override.conf' '/mnt/sysroot/etc/systemd/system/insights-client-boot.service.d/override.conf'",
			},
		},
		"rhc": {
			subOpts: subscription.ImageOptions{
				Organization:  "theorg",
				ActivationKey: "thekey",
				BaseUrl:       "https://example.com/baseurl",
				Rhc:           true,
			},
			expected: []string{
				"cp -a '/etc/systemd/system/insights-client-boot.service.d/override.conf' '/mnt/sysroot/etc/systemd/system/insights-client-boot.service.d/override.conf'",
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			p := &OSFromContainer{Subscription: &tc.subOpts}
			_, err := p.subscriptionStages()
			require.NoError(t, err)

			script := postScriptFrom(t, p)
			for _, exp := range tc.expected {
				assert.Contains(t, script, exp)
			}
			for _, notExp := range tc.notExpected {
				assert.NotContains(t, script, notExp)
			}
		})
	}
}

// The drop-in only runs if Anaconda finds it, so it must land in the exact
// directory Anaconda globs.
func TestOSFromContainerSubscriptionPostScriptPath(t *testing.T) {
	p := &OSFromContainer{
		Subscription: &subscription.ImageOptions{
			Organization:  "theorg",
			ActivationKey: "thekey",
			BaseUrl:       "https://example.com/baseurl",
		},
	}

	stages, err := p.subscriptionStages()
	require.NoError(t, err)

	var mkdirPaths, copyDestinations []string
	for _, stage := range stages {
		switch options := stage.Options.(type) {
		case *osbuild.MkdirStageOptions:
			for _, p := range options.Paths {
				mkdirPaths = append(mkdirPaths, p.Path)
			}
		case *osbuild.CopyStageOptions:
			for _, p := range options.Paths {
				copyDestinations = append(copyDestinations, p.To)
			}
		}
	}

	assert.Contains(t, mkdirPaths, "/usr/share/anaconda/post-scripts")
	assert.Contains(t, copyDestinations, "tree:///usr/share/anaconda/post-scripts/50-osbuild-subscription.ks")
}
