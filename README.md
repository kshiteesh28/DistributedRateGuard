# RateGuard

RateGuard is a distributed rate limiter project focused on enforcing API quotas reliably under concurrent load.

## Overview

The design uses a C++ service with gRPC and Protocol Buffers, Redis Cluster for distributed quota state, and etcd for coordination. Prometheus metrics and Docker support observability and local development.

## Engineering focus

- Enforce request quotas across multiple service instances.
- Address race conditions that can allow concurrent requests to exceed a quota, using atomic compare-and-swap.
- Evaluate the trade-off between fair request admission and throughput.

## Reported outcome

The project reports 58% fewer API rejections and no quota violations after the atomicity fix. These are project-reported results; a reproducible benchmark is not included in this repository yet.

## Repository status

This repository currently contains the project overview only. Implementation source code is not included.
