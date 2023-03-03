// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package recommend

import (
	"fmt"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"
	"strings"

	"github.com/clarketm/json"
	"github.com/fatih/color"
	pol "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	log "github.com/sirupsen/logrus"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/yaml"
)

func addPolicyRule(policy *pol.KubeArmorPolicy, r pol.KubeArmorPolicySpec) {

	if len(r.File.MatchDirectories) != 0 || len(r.File.MatchPaths) != 0 {
		policy.Spec.File = r.File
	}
	if len(r.Process.MatchDirectories) != 0 || len(r.Process.MatchPaths) != 0 {
		policy.Spec.Process = r.Process
	}
	if len(r.Network.MatchProtocols) != 0 {
		policy.Spec.Network = r.Network
	}
}

func mkPathFromTag(tag string) string {
	r := strings.NewReplacer(
		"/", "-",
		":", "-",
		"\\", "-",
		".", "-",
		"@", "-",
	)
	return r.Replace(tag)
}

func (img *ImageInfo) createKubeArmorPolicy(ms MatchSpec) (pol.KubeArmorPolicy, error) {
	policy := pol.KubeArmorPolicy{
		Spec: pol.KubeArmorPolicySpec{
			Severity: 1, // by default
			Selector: pol.SelectorType{
				MatchLabels: map[string]string{}},
		},
	}
	policy.APIVersion = "security.kubearmor.com/v1"
	policy.Kind = "KubeArmorPolicy"

	policy.ObjectMeta.Name = img.getPolicyName(ms.Name)

	if img.Namespace != "" {
		policy.ObjectMeta.Namespace = img.Namespace
	}

	policy.Spec.Action = ms.Spec.Action
	policy.Spec.Severity = ms.Spec.Severity
	if ms.Spec.Message != "" {
		policy.Spec.Message = ms.Spec.Message
	}
	if len(ms.Spec.Tags) > 0 {
		policy.Spec.Tags = ms.Spec.Tags
	}

	if len(img.Labels) > 0 {
		policy.Spec.Selector.MatchLabels = img.Labels
	} else {
		repotag := strings.Split(img.RepoTags[0], ":")
		policy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] = repotag[0]
	}

	addPolicyRule(&policy, ms.Spec)
	return policy, nil
}

// TODO: Add more policies (use cases)
func (img *ImageInfo) createKyvernoPolicy(ms MatchSpec) (kyvernov1.Policy, error) {
	switch ms.Name {
	case "restrict-automount-sa-token":
		return createRestrictAutomountSATokenPolicy(ms, img)
	case "drop-unused-capabilities":
		return createDropUnusedCapabilitiesPolicy(ms, img)
	}
	return kyvernov1.Policy{}, fmt.Errorf("unknown policy name: %s", ms.Name)
}

func createRestrictAutomountSATokenPolicy(ms MatchSpec, img *ImageInfo) (kyvernov1.Policy, error) {
	policy := kyvernov1.Policy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "kyverno.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: img.getPolicyName(ms.Name),
			Annotations: map[string]string{
				"policies.kyverno.io/title":      "Restrict Auto-Mount of Service Account Tokens",
				"policies.kyverno.io/minversion": "1.6.0",
				"policies.kyverno.io/description": "The pods matched in the policy don't access the service account " +
					"token, so the service account token should not be mounted to the pod.",
			},
			Namespace: img.Namespace,
		},
	}
	policySpec := ms.KyvernoPolicySpec.DeepCopy()
	policySpec.Rules[0].MatchResources.Any[0].ResourceDescription.Selector = &metav1.LabelSelector{
		MatchLabels: img.Labels,
	}
	policy.Spec = *policySpec
	return policy, nil
}

func createDropUnusedCapabilitiesPolicy(ms MatchSpec, img *ImageInfo) (kyvernov1.Policy, error) {
	policy := kyvernov1.Policy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "kyverno.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: img.getPolicyName(ms.Name),
			Annotations: map[string]string{
				"policies.kyverno.io/title":       "Drop capabilites not used by container",
				"policies.kyverno.io/minversion":  "1.6.0",
				"policies.kyverno.io/description": "Capabilities that are not used by pods should be dropped.",
			},
			Namespace: img.Namespace,
		},
	}
	policySpec := ms.KyvernoPolicySpec.DeepCopy()
	policySpec.Rules[0].MatchResources.Any[0].ResourceDescription.Selector = &metav1.LabelSelector{
		MatchLabels: img.Labels,
	}
	// TODO: Remove this hardcoded capability
	capability := "NET_ADMIN"
	jmesPath := ":{{ request.object.spec.[ephemeralContainers, initContainers, containers][].securityContext.capabilities.drop[] }}"
	policySpec.Rules[0].Validation.Deny.AnyAllConditions = apiextensions.JSON{
		Raw: []byte(fmt.Sprintf(`[{"key": ["` + capability + `"], "operator": "AnyNotIn", "value": "` + jmesPath + `"}]`)),
	}
	policySpec.Rules[0].Validation.Message = fmt.Sprintf("Unused capability '%s' should be dropped.", capability)
	policy.Spec = *policySpec
	return policy, nil
}

func (img *ImageInfo) checkPreconditions(ms MatchSpec) bool {
	var matches []string
	for _, preCondition := range ms.Precondition {
		matches = append(matches, checkForSpec(filepath.Join(preCondition), img.FileList)...)
		if strings.Contains(preCondition, "OPTSCAN") {
			return true
		}
	}
	return len(matches) >= len(ms.Precondition)
}

func matchTags(ms MatchSpec) bool {
	if len(options.Tags) <= 0 {
		return true
	}
	for _, t := range options.Tags {
		if slices.Contains(ms.Spec.Tags, t) ||
			(slices.Contains(ms.KyvernoPolicyTags, t) &&
				ms.KyvernoPolicySpec != nil) {
			return true
		}
	}
	return false
}

func (img *ImageInfo) writePolicyFile(ms MatchSpec) {
	var policy interface{}
	var err error
	if ms.KyvernoPolicySpec != nil {
		// TODO: After API is implemented, make this policy based on results from API
		policy, err = img.createKyvernoPolicy(ms)
		policy = policy.(kyvernov1.Policy)
	} else {
		policy, err = img.createKubeArmorPolicy(ms)
		policy = policy.(pol.KubeArmorPolicy)
	}
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"image": img, "spec": ms,
		}).Error("create policy failed, skipping")

	}

	outFile := img.getPolicyFile(ms.Name)
	_ = os.MkdirAll(filepath.Dir(outFile), 0750)

	f, err := os.Create(filepath.Clean(outFile))
	if err != nil {
		log.WithError(err).Error(fmt.Sprintf("create file %s failed", outFile))

	}

	arr, _ := json.Marshal(policy)
	yamlArr, _ := yaml.JSONToYAML(arr)
	if _, err := f.WriteString(string(yamlArr)); err != nil {
		log.WithError(err).Error("WriteString failed")
	}
	if err := f.Sync(); err != nil {
		log.WithError(err).Error("file sync failed")
	}
	if err := f.Close(); err != nil {
		log.WithError(err).Error("file close failed")
	}
	_ = ReportRecord(ms, outFile)
	color.Green("created policy %s ...", outFile)

}

func (img *ImageInfo) getPolicyFromImageInfo() {
	if img.OS != "linux" {
		color.Red("non-linux platforms are not supported, yet.")
		return
	}
	idx := 0
	if err := ReportStart(img); err != nil {
		log.WithError(err).Error("report start failed")
		return
	}
	var ms MatchSpec
	var err error

	err = createRuntimePolicy(img)
	if err != nil {
		log.Infof("No runtime policy generated for %s/%s/%s", img.Namespace, img.Deployment, img.Name)
	}

	ms, err = getNextRule(&idx)
	for ; err == nil; ms, err = getNextRule(&idx) {
		// matches preconditions

		if !matchTags(ms) {
			continue
		}

		if !img.checkPreconditions(ms) {
			continue
		}
		img.writePolicyFile(ms)
	}

	_ = ReportSectEnd(img)
}
