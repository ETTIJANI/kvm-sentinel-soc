#!/usr/bin/env python3
"""simulate_attack.py — realistic SSH brute force against the lab honeypot.

This is the "Simulator" agent of the assignment: it produces the failed
authentications that the SOC pipeline is supposed to detect, without needing a
classroom full of students.

It performs *real* SSH handshakes (paramiko), so the honeypot logs exactly the
same lines it would log for a live attacker:

    Failed password for root from <ip> port <p> ssh2
    Invalid user admin from <ip> port <p>
    Failed password for invalid user admin from <ip> port <p> ssh2

Usage (inside the simulator container, on the honeypot network):

    python3 simulate_attack.py --target ssh-honeypot --port 2222

Usage (from vm-honeypot host, against the published port):

    docker compose run --rm simulator --target ssh-honeypot --port 2222

Every 17th attempt logs in with the fake weak credential root/toor, which gives
the SOC a "successful breach" event to reason about — a much better story than
failures alone.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import paramiko

LOG = logging.getLogger("simulator")

DEFAULT_USERS = ["root", "admin", "oracle", "ubuntu", "test", "postgres", "pi", "user"]
DEFAULT_PASSWORDS = [
    "123456",
    "password",
    "root",
    "toor",
    "admin",
    "ubuntu",
    "letmein",
    "qwerty",
    "12345678",
    "P@ssw0rd",
]
SUCCESS_USER = "root"
SUCCESS_PASSWORD = "toor"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Stats:
    attempts: int = 0
    failures: int = 0
    successes: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)

    def summary(self) -> str:
        elapsed = max(time.time() - self.started_at, 0.001)
        rate = self.attempts / elapsed
        return (
            f"attempts={self.attempts} failures={self.failures} successes={self.successes} "
            f"errors={self.errors} elapsed={elapsed:.1f}s rate={rate:.1f}/s"
        )


def try_login(host: str, port: int, username: str, password: str, timeout: float) -> str:
    """Return one of: 'success', 'auth_failed', 'error'."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return "success"
    except paramiko.AuthenticationException:
        return "auth_failed"
    except (socket.timeout, TimeoutError):
        return "error"
    except (paramiko.SSHException, OSError) as exc:
        LOG.debug("connection error for %s@%s: %s", username, host, exc)
        return "error"
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate SSH brute-force attempts against the lab honeypot",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--target", default=os.environ.get("TARGET_HOST", "10.10.0.10"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TARGET_PORT", "22")))
    parser.add_argument(
        "--attempts-per-round",
        type=int,
        default=int(os.environ.get("ATTEMPTS_PER_ROUND", "40")),
        help="number of SSH attempts before sleeping",
    )
    parser.add_argument("--rounds", type=int, default=1, help="0 = run until interrupted")
    parser.add_argument("--delay", type=float, default=float(os.environ.get("DELAY", "0.4")))
    parser.add_argument("--users", default=",".join(DEFAULT_USERS), help="comma separated usernames")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-attempt socket timeout")
    parser.add_argument(
        "--no-success",
        action="store_true",
        help="never use the fake root/toor credential (failures only)",
    )
    parser.add_argument("--seed", type=int, default=None, help="deterministic ordering (for demos)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)sZ %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.Formatter.converter = time.gmtime

    if args.seed is not None:
        random.seed(args.seed)

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    if not users:
        LOG.error("no usernames provided")
        return 2

    LOG.info(
        "starting simulated brute force: %s:%s users=%s attempts/round=%s rounds=%s delay=%.2fs",
        args.target,
        args.port,
        ",".join(users),
        args.attempts_per_round,
        args.rounds if args.rounds else "infinite",
        args.delay,
    )

    stats = Stats()
    round_index = 0
    exit_code = 0

    try:
        while args.rounds == 0 or round_index < args.rounds:
            round_index += 1
            LOG.info("round %s", round_index)
            for _ in range(args.attempts_per_round):
                stats.attempts += 1

                # Every 17th attempt is the "successful breach" storyline.
                if not args.no_success and stats.attempts % 17 == 0:
                    username, password = SUCCESS_USER, SUCCESS_PASSWORD
                else:
                    username = random.choice(users)
                    password = random.choice(DEFAULT_PASSWORDS)

                outcome = try_login(args.target, args.port, username, password, args.timeout)
                if outcome == "success":
                    stats.successes += 1
                    LOG.warning("[%s] login SUCCEEDED %s:%s (fake credential)", utc_now(), username, password)
                elif outcome == "auth_failed":
                    stats.failures += 1
                    LOG.info("[%s] auth failed %s:%s", utc_now(), username, password)
                else:
                    stats.errors += 1
                    LOG.warning("[%s] connection error while trying %s", utc_now(), username)

                sleep_for = args.delay * random.uniform(0.7, 1.3)
                if sleep_for > 0:
                    time.sleep(sleep_for)

            if args.rounds == 0 or round_index < args.rounds:
                pause = 2.0 + random.uniform(0.0, 1.0)
                LOG.info("round %s done, pausing %.1fs", round_index, pause)
                time.sleep(pause)
    except KeyboardInterrupt:
        LOG.info("interrupted by operator")
    finally:
        LOG.info("summary: %s", stats.summary())

    if stats.attempts > 0 and stats.failures == 0 and stats.successes == 0:
        LOG.error(
            "every attempt failed at the transport level. Check that %s:%s is reachable "
            "and that the honeypot container is up (docker compose ps).",
            args.target,
            args.port,
        )
        exit_code = 2

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
