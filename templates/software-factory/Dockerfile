# Software Factory MicroVM Image
#
# Extends the base sandbox runtime with Node.js 22, opencode (AI coding agent),
# AWS CDK, and ripgrep. Designed for AI-driven coding workflows where agents
# write, test, and deploy code inside isolated MicroVMs.
#
# Tested tools: opencode 1.18.35, Node.js 22, CDK CLI, ripgrep 14.1.1
# Tested with: Amazon Bedrock via egress proxy adapter

FROM public.ecr.aws/amazonlinux/amazonlinux:2023
WORKDIR /var/task

# Base system packages (same as default image)
RUN dnf -y --allowerasing install amazon-efs-utils nfs-utils python3.13 git jq iptables iproute tar gzip \
    && dnf clean all && rm -rf /var/cache/dnf
RUN python3.13 -m ensurepip --upgrade \
    && python3.13 -m pip install --no-cache-dir --upgrade pip
RUN ln -sf /usr/bin/python3.13 /usr/local/bin/python3 \
    && ln -sf /usr/bin/python3.13 /usr/local/bin/python

# --- Software Factory additions ---

# Node.js 22 + npm
RUN dnf -y install nodejs22 npm && dnf clean all

# ripgrep (not in AL2023 dnf — install from GitHub release)
RUN curl -fsSL https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz \
    | tar xz --strip-components=1 -C /usr/local/bin ripgrep-14.1.1-aarch64-unknown-linux-gnu/rg

# npm global packages (installed with node18 which comes as a dependency)
RUN npm install -g opencode-ai@1.18.35 aws-cdk

# Make Node.js 22 the default (AL2023 installs as node-22, not node22)
RUN ln -sf /usr/bin/node-22 /usr/bin/node

# Git identity in /etc/gitconfig (readable by uid 1000, unlike /root/.gitconfig)
RUN git config --system user.name "software-factory[bot]" \
    && git config --system user.email "software-factory@users.noreply.github.com"

# XDG dirs writable by uid 1000 (opencode, npm cache, etc.)
RUN mkdir -p /tmp/.local/share /tmp/.local/state /tmp/.config /tmp/.cache \
    && chmod -R 777 /tmp/.local /tmp/.config /tmp/.cache
ENV XDG_DATA_HOME=/tmp/.local/share
ENV XDG_STATE_HOME=/tmp/.local/state
ENV XDG_CONFIG_HOME=/tmp/.config
ENV XDG_CACHE_HOME=/tmp/.cache

# Bedrock proxy adapter (bridges Node.js AI SDK to the egress proxy)
COPY templates/software-factory/bedrock-adapter.js /opt/bedrock-adapter.js

# --- End Software Factory additions ---

# Sandbox runtime (Python packages)
COPY pyproject.toml uv.lock ./
RUN python3.13 -m pip install --no-cache-dir uv \
    && uv export --frozen --no-dev --no-emit-workspace --extra runtime --format requirements-txt > requirements.txt \
    && python3.13 -m pip install --no-cache-dir -r requirements.txt \
    && python3.13 -m pip install --no-cache-dir boto3
COPY runtime runtime
COPY protocol protocol
CMD ["python3.13", "-m", "runtime"]
