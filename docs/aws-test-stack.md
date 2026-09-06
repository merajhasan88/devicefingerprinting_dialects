# The AWS test stack — and the rules for using it

**Read this before running any `aws` command.** The stack is small, deliberately cheap, and shared
with another Claude Code session working on the Flutter/Android reference client. The account is a
personal one on a tight budget, not a corporate sandbox.

## The standing conditions

These are the owner's conditions, not suggestions.

1. **The monthly budget is about PKR 500 (~USD 1.80).** A single RDS instance left running for a
   week exceeds it several times over. Cost is the binding constraint on every decision here.
2. **Never create AWS resources without being asked in the current session.** Not "it would be
   convenient to spin up a database to test against" — ask first, every time.
3. **Never delete or stop anything you did not create in the current session.** Another session may
   be mid-test against it. Run the inventory command below and look before touching anything.
4. **Tear down what you create, in the same session.** An RDS instance is created for a test run
   and deleted when that run finishes. Nothing is left overnight.
5. **Never allocate an Elastic IP.** One was allocated once and released the same day on the owner's
   instruction; it accrues roughly USD 3.60/month, which is most of the monthly budget. The
   consequence — that the EC2 public IP changes on every start — is accepted deliberately.
6. **Stop the EC2 instance, do not terminate it.** Terminating destroys hours of setup (Python venv
   and Flask dependencies, pyodbc, msodbcsql18, mssql-tools18, Redis with AOF, Caddy, the systemd
   unit, the RDS CA bundle). Stopped it costs about USD 0.64/month in EBS.
7. **No NAT Gateways, no new VPCs.** A NAT Gateway alone is roughly USD 33/month. Everything lives
   in the default VPC with public subnets by design.

## Check before you touch — always

```bash
aws ec2 describe-instances --instance-ids i-0559685f02c4013b1 \
  --query 'Reservations[].Instances[].[State.Name,PublicIpAddress]' --output text
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceStatus]' --output text
aws ec2 describe-addresses  --query 'length(Addresses)'  --output text   # must be 0
aws rds describe-db-snapshots --snapshot-type manual --query 'length(DBSnapshots)' --output text  # must be 0
```

If an RDS instance is running that you did not create, **assume the other session is using it** and
leave it alone.

## What exists

| | |
|---|---|
| Account / region | `471112581938`, **us-west-2** |
| EC2 | `i-0559685f02c4013b1`, `t4g.micro`, us-west-2a, key pair `devicetrust-key` |
| EC2 state | **stopped** — no public IP until started |
| Security groups | `sg-0a7e35ab397d765e8` **devicetrust-app**, `sg-0ed31391aa47bb8e7` **devicetrust-db** |
| DB subnet group | `devicetrust-subnets` |
| RDS | **none** — created per test run, deleted after |
| Elastic IPs / snapshots | **none, and must stay none** |

`devicetrust-db` already allows 5432 and 1433 **from the app security group only**. The databases
are never publicly accessible; reach them from the EC2 host.

## The server on that instance

- Runs as the systemd unit **`devicetrust`**, `/opt/device_trust_server.py`, interpreter
  `/opt/devicetrust-venv/bin/python3`.
- Config is a drop-in at `/etc/systemd/system/devicetrust.service.d/test.conf` overriding
  `ExecStart` with the environment for the run. Base config is `/etc/devicetrust.env` (root, 600 —
  never print its contents).
- **Caddy** terminates TLS on a `nip.io` hostname derived from the current public IP, e.g. public IP
  `54.184.195.85` → `https://54-184-195-85.nip.io`. Because there is no Elastic IP, **the hostname
  changes every time the instance starts**: update the site block in `/etc/caddy/Caddyfile` and
  reload, and Let's Encrypt reissues automatically.
- **Redis** is local with AOF enabled, used for the access-proof nonce store when
  `NONCE_BACKEND=redis`.
- SSH: `ssh -i ~/.ssh/id_ed25519 ubuntu@<public-ip>`.

## Bringing a database up, if you have been asked to

Always `--backup-retention-period 0` on create and `--skip-final-snapshot --delete-automated-backups`
on delete. Those three flags are what guarantee no snapshot survives, which the owner checks.

```bash
# PostgreSQL is faster to provision (~8 min) than SQL Server (~25 min).
aws rds create-db-instance \
  --db-instance-identifier devicetrust-pg --db-instance-class db.t4g.micro \
  --engine postgres --allocated-storage 20 --storage-type gp2 \
  --master-username dtadmin --master-user-password "file://<path-to-600-file>" \
  --db-subnet-group-name devicetrust-subnets \
  --vpc-security-group-ids sg-0ed31391aa47bb8e7 \
  --no-publicly-accessible --backup-retention-period 0 --no-multi-az \
  --no-auto-minor-version-upgrade --no-deletion-protection

aws rds delete-db-instance --db-instance-identifier devicetrust-pg \
  --skip-final-snapshot --delete-automated-backups
```

Instance classes: `db.t4g.micro` for PostgreSQL, `db.t3.micro` for `sqlserver-ex` (SQL Server
Express does not offer Graviton). Never larger.

Never put a password on the command line. Write it to a `chmod 600` file and pass
`--master-user-password "file://..."`.

## Costs, so the trade-offs are explicit

| Resource | Cost | Note |
|---|---|---|
| EC2 `t4g.micro` running | ~USD 0.008/hr | stop it when not testing |
| EC2 stopped | ~USD 0.64/month | EBS only — this is the cheap resting state |
| RDS `db.t4g.micro` / `db.t3.micro` | ~USD 0.02/hr | **delete after the run** |
| Elastic IP | ~USD 3.60/month | **forbidden** |
| NAT Gateway | ~USD 33/month | **forbidden** |
| RDS snapshot | storage-priced | must never exist |

## If you are unsure

Ask. The owner would rather answer a question than discover a running instance later. Destroying
infrastructure is irreversible and creating it costs money — neither is a decision to make on your
own initiative.
