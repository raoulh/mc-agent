
APPNAME = mc-agent

TAGS = ""
BUILD_FLAGS = "-v"
#LDFLAGS = "-H windowsgui" #this prevents opening of console on windows

.PHONY: build clean

res_windows.syso:
	go get -v github.com/akavel/rsrc
	rsrc -ico icon.ico -o res_windows.syso

build: $(GENERATED)
	go install $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -tags '$(TAGS)'
	cp '$(GOPATH)/bin/$(APPNAME)' .

windows: $(GENERATED)
	go install $(BUILD_FLAGS) -ldflags '$(LDFLAGS) -H windowsgui' -tags '$(TAGS)'
	cp '$(GOPATH)/bin/$(APPNAME)' .

clean:
	go clean -i ./...

