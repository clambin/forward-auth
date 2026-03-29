FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26 AS builder

ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ENV VERSION=$VERSION

WORKDIR /app/
ADD . .
RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-X main.version=$VERSION" \
    -o forward-auth \
    .

FROM alpine

WORKDIR /app
COPY --from=builder /app/forward-auth /app/forward-auth

RUN /usr/sbin/addgroup app
RUN /usr/sbin/adduser app -G app -D
USER app

ENTRYPOINT ["/app/forward-auth"]
CMD []
