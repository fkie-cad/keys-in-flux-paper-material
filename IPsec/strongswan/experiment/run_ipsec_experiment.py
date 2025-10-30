#!/usr/bin/env python3
"""
run_ipsec_experiment.py

Python rewrite of IPsec/strongSwan key lifecycle experiment
Provides better subprocess management and LLDB control

Usage:
    sudo python3 run_ipsec_experiment.py --workflow=full --traffic
"""

import subprocess
import argparse
import os
import sys
import time
import signal
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple
import socket
import struct

# Try to import python-vici for direct VICI protocol communication
try:
    import vici
    HAS_VICI = True
except ImportError:
    HAS_VICI = False
    print("[WARN] python-vici not installed, falling back to swanctl")
    print("[INFO] Install with: pip3 install vici")

#=============================================================================
# Configuration
#=============================================================================

class Config:
    """Experiment configuration"""
    # Network
    LEFT_NS = "left"
    RIGHT_NS = "right"
    LEFT_IP = "10.0.0.1"
    RIGHT_IP = "10.0.0.2"
    LEFT_VETH = "veth-left"
    RIGHT_VETH = "veth-right"

    # strongSwan
    LEFT_CONF_DIR = "/etc/strongswan-left"
    RIGHT_CONF_DIR = "/etc/strongswan-right"
    LEFT_VICI = "unix:///run/left.charon.vici"
    RIGHT_VICI = "unix:///run/right.charon.vici"
    LEFT_VICI_SOCKET = "/run/left.charon.vici"
    RIGHT_VICI_SOCKET = "/run/right.charon.vici"

    # Experiment
    HTTP_PORT = 8080

    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = self.script_dir / "results" / self.timestamp
        self.userspace_dir = self.output_dir / "userspace"
        self.kernel_dir = self.output_dir / "kernel"
        self.network_dir = self.output_dir / "network"
        self.experiment_log = self.output_dir / "experiment.log"
        self.strongswan_logs_dir = self.output_dir / "strongswan_logs"

#=============================================================================
# Logging
#=============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    COLORS = {
        'DEBUG': '\033[0;36m',    # Cyan
        'INFO': '\033[0;34m',     # Blue
        'WARNING': '\033[1;33m',  # Yellow
        'ERROR': '\033[0;31m',    # Red
        'CRITICAL': '\033[1;31m', # Bold Red
        'SUCCESS': '\033[0;32m',  # Green
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}[{record.levelname[0]}]{self.RESET}"
        return super().format(record)

# Add SUCCESS level
logging.SUCCESS = 25  # Between INFO and WARNING
logging.addLevelName(logging.SUCCESS, 'SUCCESS')

def success(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.SUCCESS):
        self._log(logging.SUCCESS, message, args, **kwargs)

logging.Logger.success = success

def setup_logging(log_file: Path):
    """Setup logging to both file and console"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # File handler (detailed)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)

    # Console handler (colored, less verbose)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(ColoredFormatter('%(levelname)s %(message)s'))
    logger.addHandler(ch)

    return logger

#=============================================================================
# Process Management
#=============================================================================

class ProcessManager:
    """Manages charon, LLDB, tcpdump processes"""

    def __init__(self, config: Config):
        self.config = config
        self.processes: Dict[str, subprocess.Popen] = {}
        self.pids: Dict[str, int] = {}
        self.logger = logging.getLogger(__name__)

    def start_process(self, name: str, cmd: List[str], **kwargs) -> subprocess.Popen:
        """Start a process and track it"""
        self.logger.debug(f"Starting {name}: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, **kwargs)
        self.processes[name] = proc
        self.pids[name] = proc.pid
        return proc

    def stop_process(self, name: str, timeout: float = 5.0):
        """Stop a tracked process"""
        if name not in self.processes:
            return

        proc = self.processes[name]
        if proc.poll() is None:  # Still running
            self.logger.debug(f"Stopping {name} (PID {proc.pid})")
            try:
                proc.terminate()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Process {name} did not terminate, killing")
                proc.kill()
                proc.wait()

        del self.processes[name]
        if name in self.pids:
            del self.pids[name]

    def cleanup_all(self):
        """Stop all tracked processes"""
        for name in list(self.processes.keys()):
            self.stop_process(name)

#=============================================================================
# Network Namespace Management
#=============================================================================

def netns_exec(netns: str, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    """Execute command in network namespace"""
    full_cmd = ['ip', 'netns', 'exec', netns] + cmd
    return subprocess.run(full_cmd, **kwargs)

def setup_netns(config: Config):
    """Setup network namespaces for left and right"""
    logger = logging.getLogger(__name__)
    logger.info("Setting up network namespaces...")

    # Create namespaces
    for ns in [config.LEFT_NS, config.RIGHT_NS]:
        subprocess.run(['ip', 'netns', 'add', ns], stderr=subprocess.DEVNULL)

    # Create veth pair
    subprocess.run([
        'ip', 'link', 'add', config.LEFT_VETH,
        'type', 'veth', 'peer', 'name', config.RIGHT_VETH
    ], stderr=subprocess.DEVNULL)

    # Assign to namespaces
    subprocess.run(['ip', 'link', 'set', config.LEFT_VETH, 'netns', config.LEFT_NS])
    subprocess.run(['ip', 'link', 'set', config.RIGHT_VETH, 'netns', config.RIGHT_NS])

    # Configure IPs
    netns_exec(config.LEFT_NS, ['ip', 'addr', 'add', f'{config.LEFT_IP}/24', 'dev', config.LEFT_VETH])
    netns_exec(config.RIGHT_NS, ['ip', 'addr', 'add', f'{config.RIGHT_IP}/24', 'dev', config.RIGHT_VETH])

    # Bring up interfaces
    for ns in [config.LEFT_NS, config.RIGHT_NS]:
        netns_exec(ns, ['ip', 'link', 'set', 'lo', 'up'])

    netns_exec(config.LEFT_NS, ['ip', 'link', 'set', config.LEFT_VETH, 'up'])
    netns_exec(config.RIGHT_NS, ['ip', 'link', 'set', config.RIGHT_VETH, 'up'])

    logger.success("Network namespaces ready")

def cleanup_netns(config: Config):
    """Cleanup network namespaces"""
    logger = logging.getLogger(__name__)
    logger.info("Cleaning up network namespaces...")

    # Copy strongSwan logs before cleanup
    for side in ['left', 'right']:
        log_src = f'/var/log/strongswan/charon_{side}'
        if os.path.exists(log_src):
            config.strongswan_logs_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(['cp', log_src, str(config.strongswan_logs_dir / f'charon_{side}')])

    # Delete namespaces (this also removes veth pairs)
    for ns in [config.LEFT_NS, config.RIGHT_NS]:
        subprocess.run(['ip', 'netns', 'del', ns], stderr=subprocess.DEVNULL)

    logger.success("Cleanup complete")

#=============================================================================
# VICI Communication
#=============================================================================

class VICIClient:
    """VICI protocol client (fallback to swanctl if python-vici not available)"""

    def __init__(self, socket_path: str, use_lib: bool = HAS_VICI):
        self.socket_path = socket_path
        self.use_lib = use_lib and HAS_VICI
        self.session = None
        self.logger = logging.getLogger(__name__)

        if self.use_lib:
            try:
                self.session = vici.Session(socket_path=socket_path)
            except Exception as e:
                self.logger.warning(f"Failed to create VICI session: {e}")
                self.use_lib = False

    def is_responsive(self) -> bool:
        """Check if VICI socket is responsive"""
        if self.use_lib and self.session:
            try:
                # Try to get version (simple operation)
                self.session.version()
                return True
            except Exception:
                return False
        else:
            # Fallback: use swanctl
            result = subprocess.run(
                ['swanctl', '--stats', '--uri', f'unix://{self.socket_path}'],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0

    def load_config(self, config_file: str) -> bool:
        """Load strongSwan configuration"""
        result = subprocess.run([
            'swanctl', '--load-all',
            '--file', config_file,
            '--uri', f'unix://{self.socket_path}'
        ], capture_output=True, text=True)

        if result.returncode != 0:
            self.logger.error(f"Failed to load config: {result.stderr}")
            return False
        return True

    def initiate(self, child: str = 'net') -> bool:
        """Initiate connection"""
        result = subprocess.run([
            'swanctl', '--initiate',
            '--child', child,
            '--uri', f'unix://{self.socket_path}'
        ], capture_output=True, text=True)

        if result.returncode != 0:
            self.logger.error(f"Failed to initiate: {result.stderr}")
            return False
        return True

#=============================================================================
# strongSwan Management
#=============================================================================

def start_charon(side: str, config: Config, proc_mgr: ProcessManager) -> Optional[int]:
    """Start charon process in network namespace"""
    logger = logging.getLogger(__name__)

    ns = config.LEFT_NS if side == 'left' else config.RIGHT_NS
    conf_dir = config.LEFT_CONF_DIR if side == 'left' else config.RIGHT_CONF_DIR
    conf_file = f'{conf_dir}/strongswan.conf'
    logfile = f'/var/log/strongswan/charon_{side}'

    logger.info(f"Starting charon ({side})...")

    # Start charon in namespace
    cmd = [
        'ip', 'netns', 'exec', ns,
        'env', f'STRONGSWAN_CONF={conf_file}',
        '/usr/lib/ipsec/charon',
        '--use-syslog', 'no',
        '--debug-dmn', '2', '--debug-lib', '2',
        '--debug-ike', '2', '--debug-knl', '2', '--debug-net', '2'
    ]

    proc = proc_mgr.start_process(
        f'charon_{side}',
        cmd,
        stdout=open(logfile, 'a'),
        stderr=subprocess.STDOUT
    )

    # Wait for VICI socket
    socket_path = config.LEFT_VICI_SOCKET if side == 'left' else config.RIGHT_VICI_SOCKET
    for _ in range(10):
        if os.path.exists(socket_path):
            vici_client = VICIClient(socket_path)
            if vici_client.is_responsive():
                logger.success(f"charon ({side}) started (PID: {proc.pid})")
                return proc.pid
        time.sleep(1)

    logger.error(f"charon ({side}) failed to start (VICI not ready)")
    return None

#=============================================================================
# LLDB Management
#=============================================================================

def start_lldb_monitoring(side: str, pid: int, config: Config, proc_mgr: ProcessManager) -> bool:
    """Start LLDB monitoring as background subprocess"""
    logger = logging.getLogger(__name__)

    output_dir = config.userspace_dir / side
    output_dir.mkdir(parents=True, exist_ok=True)

    monitoring_script = config.script_dir / "monitoring_ipsec.py"
    log_file = output_dir / "lldb.log"

    logger.info(f"Attaching LLDB to {side} charon (PID {pid})...")

    # Set environment for monitoring script
    env = os.environ.copy()
    env['IPSEC_NETNS'] = side
    env['IPSEC_OUTPUT_DIR'] = str(output_dir)

    # Start LLDB
    proc = proc_mgr.start_process(
        f'lldb_{side}',
        [
            'lldb',
            '-p', str(pid),
            '-o', f'command script import {monitoring_script}'
        ],
        env=env,
        stdout=open(log_file, 'w'),
        stderr=subprocess.STDOUT
    )

    logger.debug(f"  LLDB started (PID: {proc.pid})")
    logger.debug(f"  Logs: {log_file}")

    # Wait for LLDB to attach and continue
    for attempt in range(20):  # 10 seconds max
        if log_file.exists():
            content = log_file.read_text()
            if 'Monitoring active' in content or 'Process' in content and 'continued' in content:
                logger.debug("  LLDB attached and process continued")
                time.sleep(0.5)  # Extra stabilization time
                return True
        time.sleep(0.5)

    logger.warning("LLDB may not have fully initialized (check logs)")
    return False

#=============================================================================
# Main Experiment
#=============================================================================

def main():
    parser = argparse.ArgumentParser(description='IPsec/strongSwan Key Lifecycle Experiment (Python)')
    parser.add_argument('--workflow', choices=['initiate', 'rekey', 'terminate', 'full'],
                       help='Automated workflow to run')
    parser.add_argument('--traffic', action='store_true',
                       help='Generate ESP traffic after events')
    parser.add_argument('--skip-lldb', action='store_true',
                       help='Skip LLDB userspace monitoring')
    parser.add_argument('--http-port', type=int, default=8080,
                       help='HTTP server port for ESP traffic')

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (use sudo)")
        sys.exit(1)

    # Setup
    config = Config()
    config.HTTP_PORT = args.http_port

    # Create directories
    for d in [config.output_dir, config.userspace_dir, config.kernel_dir,
              config.network_dir, config.strongswan_logs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Setup logging
    logger = setup_logging(config.experiment_log)
    logger.info("IPsec/strongSwan Key Lifecycle Experiment (Python)")
    logger.info("=" * 50)

    # Process manager
    proc_mgr = ProcessManager(config)

    # Signal handler for cleanup
    def signal_handler(sig, frame):
        logger.warning("Interrupted")
        proc_mgr.cleanup_all()
        cleanup_netns(config)
        sys.exit(130)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Setup network
        cleanup_netns(config)  # Clean any previous state
        setup_netns(config)

        # Start charon processes
        left_pid = start_charon('left', config, proc_mgr)
        if not left_pid:
            logger.error("Failed to start left charon")
            return 1

        right_pid = start_charon('right', config, proc_mgr)
        if not right_pid:
            logger.error("Failed to start right charon")
            return 1

        # Start LLDB monitoring (unless skipped)
        if not args.skip_lldb:
            if not start_lldb_monitoring('left', left_pid, config, proc_mgr):
                logger.warning("LLDB monitoring may have issues")

            # Verify VICI is still responsive
            logger.info("Verifying VICI socket after LLDB attachment...")
            vici_left = VICIClient(config.LEFT_VICI_SOCKET)

            for attempt in range(10):
                if vici_left.is_responsive():
                    logger.success("VICI socket is responsive")
                    break
                logger.debug(f"VICI not responsive (attempt {attempt+1}/10)")
                time.sleep(1)
            else:
                logger.error("VICI socket not responsive after LLDB attachment!")
                logger.error("Try running with --skip-lldb")
                return 1
        else:
            logger.info("Skipping LLDB monitoring (--skip-lldb)")

        logger.success("Experiment setup complete!")
        logger.info(f"Output directory: {config.output_dir}")

        # If workflow specified, run it
        if args.workflow:
            logger.info(f"Running automated workflow: {args.workflow}")
            # TODO: Implement workflows
            logger.warning("Automated workflows not yet implemented in Python version")
            logger.info("Use interactive mode or bash script for now")
        else:
            logger.info("Setup complete. Press Ctrl+C to exit.")
            while True:
                time.sleep(1)

    except Exception as e:
        logger.error(f"Experiment failed: {e}", exc_info=True)
        return 1
    finally:
        # Cleanup
        logger.info("Cleaning up...")
        proc_mgr.cleanup_all()
        cleanup_netns(config)
        logger.success("Experiment complete!")
        logger.info(f"Results saved to: {config.output_dir}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
