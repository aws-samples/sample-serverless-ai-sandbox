# Cost Model & Measurements

## Pricing Components

The sandbox runs entirely on AWS consumption-priced services. There is no license fee.

### Per-Session Costs

| Component | Pricing Basis | Typical Per-Session Cost |
|-----------|--------------|------------------------|
| **Lambda MicroVM** | Duration (GB-seconds) | ~$0.03-0.08/hr (2GB, active) |
| **Step Functions** | State transitions | ~$0.0003/session (Standard workflow) |
| **DynamoDB** | Read/write capacity units | ~$0.001/session lifecycle |
| **API Gateway** | Per request | ~$0.000001/API call |
| **Fargate Proxy** | vCPU + memory/hr | ~$0.05/hr (shared across sessions) |
| **NLB** | LCU-hours | ~$0.006/hr (shared) |
| **CloudWatch** | Metrics + logs | ~$0.01/hr (shared) |

### Idle vs Active Cost

| State | What Runs | Approximate Cost |
|-------|-----------|-----------------|
| **RUNNING (active)** | MicroVM + proxy + polling | ~$0.08/hr per session |
| **RUNNING (idle)** | MicroVM + polling only | ~$0.05/hr per session |
| **SUSPENDED** | Nothing (state in snapshot) | $0.00/hr (storage only) |
| **TERMINATED** | Nothing | $0.00 |

### Shared Infrastructure (Fixed Costs)

These run regardless of session count:

| Component | Monthly Cost (idle) | Monthly Cost (active) |
|-----------|--------------------|-----------------------|
| Fargate Proxy (1 task, 0.25 vCPU / 0.5 GB) | ~$9 | ~$9 |
| NLB | ~$16 | ~$16 |
| NAT Gateway | ~$32 | ~$32 + data transfer |
| CloudWatch Dashboard | $3 | $3 |
| **Total shared baseline** | **~$60/month** | **~$60/month** |

### Bedrock Costs (Usage-Based)

Bedrock costs are separate and depend on model and usage:

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|----------------------|----------------------|
| Claude Sonnet 4 | $3.00 | $15.00 |
| Claude Haiku 3.5 | $0.80 | $4.00 |

These are billed to the sandbox execution role's account.

## Cost Scenarios

### Scenario 1: Development (5 sessions/day, 1hr each)
```
Lambda MicroVM:   5 sessions × 1hr × $0.08        = $0.40/day = $12/month
Step Functions:   5 sessions × $0.0003             = negligible
DynamoDB:         5 sessions × ~10 ops             = negligible
Shared infra:     $60/month
Total:            ~$72/month
```

### Scenario 2: Production (100 sessions/day, 30min avg)
```
Lambda MicroVM:   100 × 0.5hr × $0.08             = $4/day = $120/month
Reaper polling:   100 × 30min × $0.002/poll        = $6/month
Shared infra:     $60/month
Total:            ~$186/month
```

### Scenario 3: Multi-Tenant SaaS (1000 sessions/day, 15min avg)
```
Lambda MicroVM:   1000 × 0.25hr × $0.08           = $20/day = $600/month
Reaper + polling: ~$50/month
Shared infra:     $60/month (scale proxy to 2 tasks: +$9)
Total:            ~$719/month
```

### Scenario 4: Heavy with Suspend/Resume (50 active, 200 suspended)
```
Active MicroVMs:  50 × 8hr × $0.08                = $32/day
Suspended:        200 × $0/hr                      = $0 (only snapshot storage)
Resume events:    ~50/day × $0.0003                = negligible
Shared infra:     $60/month
Total:            ~$1,020/month
```

## Cost Optimization

### Suspend Aggressively
Suspended sessions cost nothing per hour. Set `idleSeconds: 60` for development,
`idleSeconds: 300` for production. Auto-resume is transparent to the user.

### Right-Size Memory
Default is 2GB. If workloads are lightweight (file manipulation, simple scripts),
reduce to 512MB or 1GB. Lambda MicroVM pricing scales linearly with memory.

### Reduce Poll Interval
The orchestrator polls MicroVM status every 30 seconds. For low-latency requirements
this is fine. For batch workloads, consider reducing poll frequency by adjusting the
Step Functions wait state.

### Share the Proxy
The Fargate proxy and NLB are shared across all sessions. One proxy task handles
hundreds of concurrent sessions. Only scale when connection throughput requires it.

### Use DynamoDB On-Demand
The table uses on-demand capacity by default. For predictable workloads, switch to
provisioned capacity with auto-scaling for ~30% (based on AWS published on-demand vs. provisioned pricing, us-east-1, as of 2026-09) savings.

## Metrics Available

The CloudWatch dashboard tracks:

| Metric | Namespace | Description |
|--------|-----------|-------------|
| `SandboxesRunning` | `AgentSandbox` | Count of RUNNING sessions |
| `SandboxesSuspended` | `AgentSandbox` | Count of SUSPENDED sessions |
| `SessionCreated` | `AgentSandbox` | Session creation events |
| `SessionTerminated` | `AgentSandbox` | Session termination events |

### Per-Session Metrics (from sandbox)

Collected via `execute_command` on the MicroVM:
- Memory usage (from `/proc/meminfo`)
- Disk usage (from `df`)
- Load average (from `/proc/loadavg`)
- Uptime (from `/proc/uptime`)

## What's Not Measured Yet

- **Per-session cost attribution**: no automatic tagging of Lambda MicroVM costs to session IDs
- **Bedrock token usage per session**: tracked by Bedrock but not aggregated per sandbox session
- **Network transfer per session**: egress through the proxy is measured at the NAT gateway level, not per session
- **Cost allocation tags**: not yet propagated to all resources (planned)

## Recommendations

1. **Tag everything**: add `SessionId` and `TenantId` tags to resources for cost allocation
2. **Set billing alarms**: CloudWatch alarm on estimated charges for the account
3. **Monitor the Reaper**: if sessions aren't being cleaned up, costs accumulate
4. **Review idle sessions weekly**: use the console's Sessions page to find long-running idle sessions
5. **Benchmark your workload**: create 10 sessions, run your typical agent task, check CloudWatch billing metrics after 24h
