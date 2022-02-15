# Environment template renderer
FROM composer22/envtpl:latest AS envtpl

# Server
#FROM alpine:latest
FROM alpine:3.15.0
ARG release_tag
LABEL Name=k8ctl-server \
      Version=${release_tag}

ENV K8CTL_SERVER_RELEASE=${release_tag}

# kubectl - Must be one version plus or minus EKS version.
# https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html
ENV KUBE_LATEST_VERSION="1.19.6"
ENV KUBE_LATEST_PATH="2021-01-05"

# aws-iam-authenticator
# https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html
ENV AUTH_LATEST_VERSION="1.21.2"
ENV AUTH_LATEST_PATH="2021-07-05"

# Helm - must be 3.x or greater
ENV HELM_LATEST_VERSION="v3.8.0"

# 1. Prepare alpine for installation.
# 2. Add additional alpine packages.
# 3. Install official Amazon EKS-vended kubectl binary and and validate openssl checksum.
# 4. Install AWS IAM Authenticator and and validate openssl checksum.
# 5. Install Helm client and validate openssl checksum.
# 6. Install k8ctl-server
# 7. Change permissions and cleanup.

RUN apk --update-cache update \
  && apk upgrade \
  && apk add --upgrade bash ca-certificates curl gettext git gzip jq openssl tar wget \
  && cd /usr/local/bin \
  && echo "====== Installing kubectl ======" \
  && curl -o kubectl https://amazon-eks.s3-us-west-2.amazonaws.com/${KUBE_LATEST_VERSION}/${KUBE_LATEST_PATH}/bin/linux/amd64/kubectl \
  && curl -o kubectl.sha256 https://amazon-eks.s3-us-west-2.amazonaws.com/${KUBE_LATEST_VERSION}/${KUBE_LATEST_PATH}/bin/linux/amd64/kubectl.sha256 \
  && openssl sha1 -sha256 -r kubectl | tr -d "*" > /tmp/kubectl.sha256 \
  && diff /tmp/kubectl.sha256 kubectl.sha256 \
  && echo "====== Installing aws-iam-authenticator ======" \
  && curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/${AUTH_LATEST_VERSION}/${AUTH_LATEST_PATH}/bin/linux/amd64/aws-iam-authenticator \
  && curl -o aws-iam-authenticator.sha256 https://amazon-eks.s3-us-west-2.amazonaws.com/${AUTH_LATEST_VERSION}/${AUTH_LATEST_PATH}/bin/linux/amd64/aws-iam-authenticator.sha256 \
  && openssl sha1 -sha256 -r aws-iam-authenticator | tr -d "*" > /tmp/aws-iam-authenticator.sha256 \
  && diff /tmp/aws-iam-authenticator.sha256 aws-iam-authenticator.sha256 \
  && echo "====== Installing helm ======" \
  && curl -o helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz https://get.helm.sh/helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz \
  && tar -xvf helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz -C /tmp \
  && cp /tmp/linux-amd64/helm /usr/local/bin/helm \
  && curl -o helm.tar.gz.sha256.origin https://get.helm.sh/helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz.sha256 \
  && openssl sha1 -sha256 -r helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz | tr -d "*" > helm.tar.gz.sha256.out \
  && sed -e s/\ *helm-${HELM_LATEST_VERSION}-linux-amd64.tar.gz//g -i helm.tar.gz.sha256.out \
  && diff helm.tar.gz.sha256.origin helm.tar.gz.sha256.out \
  && echo "====== Installing k8ctl-server ======" \
  && mkdir -p /usr/local/docker/k8ctl-server/configmaps \
  && curl -f -o /usr/local/docker/k8ctl-server/k8ctl-server \
      -L https://github.com/composer22/k8ctl-server/releases/download/${release_tag}/k8ctl-server-linux-amd64 \
  && echo "====== Final cleanup ======" \
  && chmod +x /usr/local/bin/kubectl /usr/local/bin/aws-iam-authenticator /usr/local/bin/helm \
  && chmod +x /usr/local/docker/k8ctl-server/k8ctl-server \
  && rm -rf /var/cache/apk/* /tmp/*

COPY --from=envtpl /bin/envtpl /usr/local/bin/envtpl
COPY ./scripts /usr/local/docker/k8ctl-server/scripts/
COPY ./docker-entrypoint.sh  /usr/local/docker/k8ctl-server/docker-entrypoint.sh

EXPOSE 8080
USER root
WORKDIR /usr/local/docker/k8ctl-server/
CMD []
ENTRYPOINT ["/usr/local/docker/k8ctl-server/docker-entrypoint.sh"]
