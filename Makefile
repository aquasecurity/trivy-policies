DYNAMIC_REGO_FOLDER=./checks/kubernetes/policies/dynamic

.PHONY: test
test:
	go test -v ./...


.PHONY: rego
rego: fmt-rego test-rego

.PHONY: test-rego
test-rego: 
	opa test checks/ lib/

.PHONY: fmt-rego
fmt-rego:
	opa fmt -w checks/ lib/

.PHONY: bundle
bundle: create-bundle verify-bundle

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: outdated-api-updated
outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak

.PHONY: docs
docs:
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...

.PHONY: create-bundle
create-bundle:
	./scripts/bundle.sh

.PHONY: verify-bundle
verify-bundle:
	cp bundle.tar.gz scripts/bundle.tar.gz
	go run ./scripts/verify-bundle.go
	rm scripts/bundle.tar.gz
