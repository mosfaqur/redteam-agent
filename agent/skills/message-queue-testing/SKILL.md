---
name: message-queue-testing
description: Test Kafka, RabbitMQ/AMQP, MQTT, ActiveMQ, and Redis Pub/Sub brokers for unauthenticated access, topic/queue enumeration, and message injection
origin: RedteamOpencode
---

# Message Queue / Broker Testing

## When to Activate

- Ports 9092/9093 (Kafka), 5672/5671 (AMQP/RabbitMQ), 15672 (RabbitMQ management API), 1883/8883 (MQTT), 61616 (ActiveMQ OpenWire), 8161 (ActiveMQ web console), 6379 (Redis, when used as a pub/sub bus rather than a datastore — cross-check with `database-services`)
- Microservice architectures with async/event-driven communication, or IoT/embedded fleets using MQTT for telemetry

## Tools

`run_tool nmap`, `kafkacat`/`kcat`, `kafka-console-consumer.sh`/`kafka-console-producer.sh`, `mosquitto_sub`/`mosquitto_pub`, `rabbitmqadmin`, `amqp-tools` (`amqp-publish`/`amqp-consume`), `curl` against management HTTP APIs.

## Methodology

### Kafka (9092/9093)

```bash
run_tool nmap -p 9092 --script kafka-info HOST
run_tool kcat -b HOST:9092 -L                      # list brokers, topics, partitions (no auth)
run_tool kcat -b HOST:9092 -C -t <topic> -o beginning -e   # consume from beginning, exit at end
run_tool kcat -b HOST:9092 -P -t <topic> <<< 'test-message'   # produce (confirm-only, use a scratch topic if possible)
```

- [ ] Unauthenticated broker (`SASL_PLAINTEXT`/`PLAINTEXT` listener with no ACLs): `kcat -L` succeeding without credentials confirms open metadata access
- [ ] Topic enumeration for sensitive names: `_schemas`, `__consumer_offsets` (internal — do not tamper), and business-named topics (`orders`, `payments`, `audit-log`, `user-events`) reachable via the same open listener
- [ ] Consumer-group hijacking: join an existing `group.id` on an unauthenticated broker to silently receive a copy of messages intended for a legitimate consumer, or to force a rebalance that starves it
- [ ] Schema Registry (port 8081, if present) unauthenticated schema disclosure — reveals message structure/field names even without reading actual topic data
- [ ] ACL/SASL misconfiguration: broker requires SASL for produce but not for `--list`/metadata fetch (partial-auth misconfig), or accepts `PLAIN` mechanism over an unencrypted listener (credential-sniffing exposure)
- [ ] Message injection impact: producing a crafted message onto a topic consumed by a downstream service (order-processing, billing, notification worker) — treat as a `vuln_confirmed` case for exploit-developer rather than sending a business-impacting payload yourself

### RabbitMQ / AMQP (5672, 15672)

```bash
run_tool nmap -p 5672,15672 --script amqp-info HOST
curl -s -u guest:guest http://HOST:15672/api/overview          # management API, default creds
curl -s -u guest:guest http://HOST:15672/api/queues            # list all queues across vhosts
run_tool amqp-consume -s HOST -q <queue> -c 1 cat               # single-message peek
```

- [ ] Default `guest:guest` credentials — RabbitMQ historically only restricts `guest` to `localhost` by default; confirm whether that restriction was actually kept when the management plugin is exposed externally
- [ ] Management HTTP API (15672) enumeration: `/api/queues`, `/api/exchanges`, `/api/bindings`, `/api/connections`, `/api/vhosts` disclose full topology, message counts, and connected client IPs/usernames without needing to touch the AMQP port itself
- [ ] Queue/exchange creation via management API if write access is unauthenticated or default-creds — can be used to bind a new queue to an existing exchange and passively intercept messages routed by topic/pattern
- [ ] `federation`/`shovel` plugin misconfig: a reachable management API with federation enabled may allow defining a new upstream that exfiltrates messages to an attacker-controlled broker — note as an escalation candidate
- [ ] Erlang cookie exposure: RabbitMQ runs on Erlang/OTP — if the distribution port (4369 epmd, then a dynamic port) is reachable and the `.erlang.cookie` is guessable/leaked, this is a full RCE primitive via the Erlang distribution protocol, not just a queue issue — hand off to exploit-developer

### MQTT (1883, 8883)

```bash
run_tool nmap -p 1883 --script mqtt-subscribe HOST
run_tool mosquitto_sub -h HOST -p 1883 -t '#' -v               # subscribe to ALL topics (wildcard)
run_tool mosquitto_pub -h HOST -p 1883 -t <topic> -m 'test'    # publish (confirm-only)
```

- [ ] Unauthenticated broker accepting `CONNECT` with no username/password — extremely common on IoT/embedded deployments
- [ ] Wildcard subscription (`#` or `+/status`) to passively enumerate the full topic tree and observe live device/telemetry traffic without any active probing — highest-value, lowest-noise first step
- [ ] Retained-message disclosure: brokers store the last message per topic with the `retain` flag; a wildcard subscribe immediately dumps historical state (last-known device config, credentials, GPS coordinates) even if no new traffic is flowing
- [ ] Topic-based ACL bypass: broker restricts publish on `device/+/command` for authenticated clients but the same restriction isn't enforced for anonymous connections, or ACL uses a prefix match that a crafted topic name (`device/../admin/command`, extra `/` segments) can evade
- [ ] Command-topic injection: if a device subscribes to a control topic (`device/<id>/cmd`) and the broker allows arbitrary publish, injecting commands is a direct device-takeover primitive — correlate with `embedded-device-testing` and treat as `vuln_confirmed`
- [ ] TLS-optional listener: broker offers both 1883 (plaintext) and 8883 (TLS) — confirm whether the plaintext listener accepts the same credentials as TLS, which would make MQTT auth trivially sniffable on the unencrypted port
- [ ] MQTT 3.1.1 vs 5.0 feature differences: v5 adds enhanced auth (`AUTH` packet) and reason codes that can leak whether a username exists vs a bad password — a distinguishable `CONNACK` reason code (`0x84` bad username/password vs `0x87` not authorized) is a user-enumeration side channel

### ActiveMQ (61616, 8161)

```bash
run_tool nmap -p 61616,8161 --script activemq-info HOST
curl -s -u admin:admin http://HOST:8161/admin/                 # web console, default creds
```

- [ ] Default `admin:admin` web console credentials
- [ ] OpenWire protocol unauthenticated access (61616) — older ActiveMQ versions allow unauthenticated `ObjectMessage` deserialization via OpenWire, a direct RCE primitive (CVE-2015-5254 class); version-fingerprint before attempting, hand off confirmed cases to exploit-developer
- [ ] Web console file-write primitive: authenticated admin console historically allowed deploying a `.war` via the Jetty file-upload endpoint — check version against known CVEs (CVE-2016-3088) rather than attempting upload directly

### Redis Pub/Sub (6379, cross-reference with `database-services`)

- [ ] If Redis is used as a message bus (`PUBLISH`/`SUBSCRIBE`) rather than a cache/datastore, an unauthenticated instance allows subscribing to arbitrary channels (`PSUBSCRIBE *`) to intercept application events in real time
- [ ] Keyspace notifications (`CONFIG SET notify-keyspace-events`) if writable — can be abused to turn Redis into a live activity monitor across the whole dataset, not just pub/sub channels

## Confirm-Only Rule

Enumeration and read-only interception (subscribe/consume, metadata listing) are sufficient to confirm exposure. Do not publish messages onto production business topics/queues, do not create durable subscriptions/queues that outlive the test, and do not attempt OpenWire/Erlang-cookie RCE primitives yourself — record as `vuln_confirmed` and hand off to exploit-developer.

## Budget

`--host-timeout 60s` per broker. Wildcard subscriptions should run for a bounded window (10-30s) to capture representative traffic, not indefinitely.
