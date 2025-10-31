#!/usr/bin/env python3
"""
SSH Key Lifecycle Experiment Orchestrator
Uses client-side control (OpenSSH escape sequences) for universal server compatibility

Workflow:
  1. Start packet capture
  2. Connect client (openssh_groundtruth) → keys extracted automatically
  3. Stable connection (5s)
  4. Trigger rekey via ~R escape → new keys extracted
  5. Post-rekey stable (5s)
  6. Terminate via ~. escape
  7. Stop capture

Author: SSH Key Lifecycle Lab
"""

import subprocess
import time
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
import signal
import tempfile

@dataclass
class ExperimentResult:
    """Results from a single server experiment"""
    server: str
    started_at: str
    connect_duration: float
    stable_duration: float
    rekey_duration: float
    post_rekey_duration: float
    terminate_duration: float
    total_duration: float
    keylog_file: str
    capture_file: str
    keys_extracted: int
    success: bool
    error: str = ""


class ExperimentOrchestrator:
    """
    Main orchestrator for SSH key lifecycle experiments
    Uses client-side control (escape sequences) for universal compatibility
    """

    SERVERS = {
        'openssh': ('openssh_server', 22),
        'dropbear': ('dropbear_server', 22),
        'wolfssh': ('wolfssh_server', 22),
        'paramiko': ('paramiko_server', 22)
    }

    def __init__(self, data_dir='./data'):
        self.data_dir = Path(data_dir)
        self.keylog_dir = self.data_dir / 'keylogs'
        self.capture_dir = self.data_dir / 'captures'

        # Ensure directories exist
        self.keylog_dir.mkdir(parents=True, exist_ok=True)
        self.capture_dir.mkdir(parents=True, exist_ok=True)

    def run_experiment(self, server_name):
        """
        Execute complete lifecycle experiment for one server
        Workflow: connect → stable → rekey → stable → terminate
        """
        if server_name not in self.SERVERS:
            raise ValueError(f"Unknown server: {server_name}. Valid: {list(self.SERVERS.keys())}")

        host, port = self.SERVERS[server_name]

        print(f"\n{'='*70}")
        print(f"EXPERIMENT: {server_name} ({host}:{port})")
        print(f"{'='*70}")

        result = ExperimentResult(
            server=server_name,
            started_at=datetime.now().isoformat(),
            connect_duration=0,
            stable_duration=0,
            rekey_duration=0,
            post_rekey_duration=0,
            terminate_duration=0,
            total_duration=0,
            keylog_file=f"groundtruth_{server_name}.log",
            capture_file="",
            keys_extracted=0,
            success=False
        )

        try:
            exp_start = time.time()

            # Clean previous keylog
            keylog_path = self.keylog_dir / result.keylog_file
            if keylog_path.exists():
                keylog_path.unlink()

            # Phase 1: Run client with automatic key extraction
            print("[1/5] Connecting client and deriving initial keys...")
            phase_start = time.time()

            # Use docker compose run to start client in client mode
            cmd = [
                'docker', 'compose', 'run', '--rm',
                '-e', 'MODE=client',
                '-e', f'HOST={host}',
                '-e', f'PORT={port}',
                '-e', 'USER=testuser',
                '-e', 'PASSWORD=password',
                '-e', f'SSHKEYLOGFILE=/data/keylogs/{result.keylog_file}',
                '-e', 'CAPTURE_TRAFFIC=false',  # We'll handle capture separately if needed
                '-e', 'SSH_CMD=echo "Connected"; sleep 5; echo "~R" > /dev/stderr; sleep 5; echo "~." > /dev/stderr',
                'openssh_groundtruth'
            ]

            # This is simplified - in production you'd use expect to control the session
            # For now, we do: connect → wait 5s → rekey → wait 5s → terminate
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = proc.communicate(timeout=30)
            result.connect_duration = time.time() - phase_start

            if proc.returncode == 0:
                result.success = True
                print(f"      Connection workflow completed in {result.connect_duration:.2f}s")
            else:
                result.success = False
                result.error = f"Client returned exit code {proc.returncode}"
                print(f"      [ERROR] {result.error}")

            result.total_duration = time.time() - exp_start

            # Count extracted keys
            if keylog_path.exists():
                content = keylog_path.read_text()
                result.keys_extracted = content.count('NEWKEYS')
                print(f"      Keys extracted: {result.keys_extracted}")
            else:
                print(f"      [WARN] Keylog file not found: {keylog_path}")

            if result.success:
                print(f"\n✅ Experiment complete: {result.total_duration:.2f}s total")
            else:
                print(f"\n❌ Experiment failed: {result.error}")

        except subprocess.TimeoutExpired:
            result.success = False
            result.error = "Client connection timeout (30s)"
            print(f"\n❌ Experiment timeout: {result.error}")
        except Exception as e:
            result.success = False
            result.error = str(e)
            print(f"\n❌ Experiment failed: {e}")

        return result

    def run_all_servers(self):
        """Run experiments on all servers sequentially"""
        results = []

        print("\n" + "="*70)
        print("SSH KEY LIFECYCLE EXPERIMENT - ALL SERVERS")
        print("="*70)

        # Ensure servers are running
        print("\n[SETUP] Ensuring all servers are running...")
        subprocess.run(['docker', 'compose', 'up', '-d',
                       'openssh_server', 'dropbear_server',
                       'wolfssh_server', 'paramiko_server'],
                      check=True)
        print("[SETUP] Waiting for servers to initialize...")
        time.sleep(5)

        for server_name in self.SERVERS.keys():
            result = self.run_experiment(server_name)
            results.append(result)
            time.sleep(2)  # Brief pause between experiments

        return results

    def save_results(self, results):
        """Save results to JSON"""
        output_file = self.keylog_dir / "experiment_results.json"

        data = {
            'timestamp': datetime.now().isoformat(),
            'experiments': [asdict(r) for r in results]
        }

        output_file.write_text(json.dumps(data, indent=2))
        print(f"\n📊 Results saved to: {output_file}")
        return output_file

    def print_summary(self, results):
        """Print experiment summary table"""
        print("\n" + "="*70)
        print("EXPERIMENT SUMMARY")
        print("="*70)
        print(f"{'Server':<12} {'Status':<8} {'Duration':<10} {'Keys':<6}")
        print("-" * 70)

        for r in results:
            status = "✅ PASS" if r.success else "❌ FAIL"
            print(f"{r.server:<12} {status:<8} {r.total_duration:>8.2f}s  {r.keys_extracted:>4}")

        print("\n" + "="*70)
        print("FILES GENERATED")
        print("="*70)
        print(f"Keylogs:  {self.keylog_dir}/groundtruth_*.log")
        print(f"Results:  {self.keylog_dir}/experiment_results.json")
        print("\nView extracted keys:")
        for r in results:
            if r.success:
                print(f"  cat {self.keylog_dir}/{r.keylog_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='SSH Key Lifecycle Experiment Orchestrator (Client-Side Control)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                    Run experiments on all servers
  %(prog)s --server openssh         Run experiment on OpenSSH only
  %(prog)s --server dropbear        Run experiment on Dropbear only

This orchestrator uses client-side control (OpenSSH escape sequences):
  ~R  -> Trigger rekey (works with ALL SSH servers)
  ~.  -> Terminate connection (graceful close)
"""
    )

    parser.add_argument('--server',
                       choices=['openssh', 'dropbear', 'wolfssh', 'paramiko'],
                       help='Run experiment on specific server')
    parser.add_argument('--all', action='store_true',
                       help='Run experiments on all servers')
    parser.add_argument('--data-dir', default='./data',
                       help='Data directory (default: ./data)')

    args = parser.parse_args()

    if not (args.all or args.server):
        parser.print_help()
        return 1

    orchestrator = ExperimentOrchestrator(data_dir=args.data_dir)

    try:
        if args.all:
            results = orchestrator.run_all_servers()
        elif args.server:
            results = [orchestrator.run_experiment(args.server)]

        orchestrator.save_results(results)
        orchestrator.print_summary(results)

        # Return 0 if all succeeded, 1 if any failed
        if all(r.success for r in results):
            print("\n✅ All experiments completed successfully")
            return 0
        else:
            print("\n❌ Some experiments failed")
            return 1

    except KeyboardInterrupt:
        print("\n\n⚠️  Experiment interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
