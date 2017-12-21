#!/bin/bash -x

set -e

echo "Build and upload binaries to calaos.fr"

if [ "x$UPLOAD_KEY" == "x"  ]; then
    echo "Error, UPLOAD_KEY is not set"
    exit 1
fi

function upload_file()
{
    FNAME=$1
    HASH=$(sha256sum $FNAME | cut -d' ' -f1)
    INSTALLPATH=$2

    echo "Uploading file $FNAME"

    curl -X POST \
        -H "Content-Type: multipart/form-data" \
        -F "upload_key=$UPLOAD_KEY" \
        -F "upload_folder=$INSTALLPATH" \
        -F "upload_sha256=$HASH" \
        -F "upload_file=@$FNAME" \
        -F "upload_force=true" \
        --progress-bar \
        https://calaos.fr/mooltipass/upload -o upload.log
    rm -f upload.log
}

BIN="mc-agent"

echo ">> Building windows bin"
export GO15VENDOREXPERIMENT=1
export CGO_ENABLED=0

export GOARCH=386
export GOOS=windows
go env
rm -f ${BIN}.exe
go get -d
go build -v -ldflags "-H windowsgui"
upload_file ${BIN}.exe "tools/windows"

echo ">> Building linux bin"
export GOARCH=amd64
export GOOS=linux
go env
rm -f $BIN ${BIN}.exe
go get -d
go build -v
upload_file ${BIN} "tools/linux"

echo ">> Building macos bin"
export GOARCH=amd64
export GOOS=darwin
go env
rm -f $BIN
go get -d
go build -v
upload_file ${BIN} "tools/macos"

