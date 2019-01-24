PKGS = $$(go list ./... | grep -v /vendor/)

default:
	go build

test:
	go clean $(PKGS)
	go test $(PKGS) -check.v -coverprofile=coverage.txt -covermode=atomic

race:
	go clean $(PKGS)
	go test -race $(PKGS) -check.v -coverprofile=coverage.txt -covermode=atomic

profile:
	go clean $(PKGS)
	make
	
clean:
	rm -rf *.prof
	go clean $(PKGS)

lint:
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	golangci-lint run