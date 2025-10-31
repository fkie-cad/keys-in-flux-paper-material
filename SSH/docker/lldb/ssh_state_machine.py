#!/usr/bin/env python3
"""
SSH Protocol State Machine

State tracking and transition management for SSH lifecycle experiments.
Automatically triggers memory dumps before/after transitions and logs events.

Author: SSH Lifecycle Experiment Framework
Date: 2025-10-24
"""

import lldb
import json
import os
from datetime import datetime
from enum import Enum

# Import our memory dump utilities
import sys
sys.path.insert(0, os.path.dirname(__file__))
import ssh_memory_dump


class SSHState(Enum):
    """SSH protocol lifecycle states"""
    PRE_CONNECT = "PRE_CONNECT"
    KEX_COMPLETE = "KEX_COMPLETE"
    ACTIVE = "ACTIVE"
    REKEY_START = "REKEY_START"
    REKEY_COMPLETE = "REKEY_COMPLETE"
    PRE_SESSION_CLOSE = "PRE_SESSION_CLOSE"  # Before exit command (file trigger)
    SESSION_CLOSED = "SESSION_CLOSED"
    CLEANUP = "CLEANUP"


class SSHStateMachine:
    """
    SSH Protocol State Machine

    Manages SSH connection lifecycle with automatic memory dumps
    at state transitions.
    """

    def __init__(self, process, output_dir, dump_type="full", enable_dumps=True):
        """
        Initialize state machine.

        Args:
            process (lldb.SBProcess): The LLDB process to monitor
            output_dir (str): Directory for dumps and logs
            dump_type (str): "full", "heap", or "keys"
            enable_dumps (bool): Enable/disable memory dumping
        """
        self.process = process
        self.output_dir = output_dir
        self.dump_type = dump_type
        self.enable_dumps = enable_dumps

        self.current_state = SSHState.PRE_CONNECT
        self.state_history = []
        self.transition_log = []

        # Event log file
        self.event_log_path = os.path.join(output_dir, "ssh_events.jsonl")

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Log initial state
        self._log_event("STATE_INIT", {
            "initial_state": self.current_state.value,
            "pid": process.GetProcessID(),
            "dump_type": dump_type,
            "dumps_enabled": enable_dumps
        })

        print(f"[STATE_MACHINE] Initialized - State: {self.current_state.value}")
        print(f"[STATE_MACHINE] Output: {output_dir}")
        print(f"[STATE_MACHINE] Dumps: {'enabled' if enable_dumps else 'disabled'} ({dump_type})")

    def transition(self, new_state, metadata=None, key_addresses=None):
        """
        Transition to a new state with automatic pre/post dumps.

        Args:
            new_state (SSHState): Target state
            metadata (dict, optional): Additional metadata to log
            key_addresses (list, optional): Key addresses for targeted dumps

        Returns:
            bool: True if transition succeeded
        """
        if not isinstance(new_state, SSHState):
            print(f"[STATE_MACHINE] ✗ Invalid state: {new_state}")
            return False

        old_state = self.current_state
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        print(f"\n[STATE_TRANSITION] {old_state.value} → {new_state.value}")

        # --- PRE-TRANSITION DUMP ---
        pre_dump_path = None
        pre_dump_bytes = 0

        if self.enable_dumps:
            pre_label = f"pre_{new_state.value.lower()}"
            print(f"[STATE_MACHINE] 📸 Pre-transition dump: {pre_label}")

            try:
                if self.dump_type == "keys" and key_addresses:
                    pre_dump_path, pre_dump_bytes, _ = ssh_memory_dump.dump_key_regions(
                        self.process, key_addresses, self.output_dir, pre_label, timestamp
                    )
                else:
                    # Always use simple dump_process_memory() (works reliably)
                    # The complex dump_heap_regions() hybrid approach has issues
                    pre_dump_path, pre_dump_bytes, _ = ssh_memory_dump.dump_process_memory(
                        self.process, self.output_dir, pre_label, timestamp
                    )
            except Exception as e:
                print(f"[STATE_MACHINE] ⚠️  Pre-dump failed: {e}")

        # --- UPDATE STATE ---
        self.current_state = new_state
        self.state_history.append((new_state, timestamp))

        # --- POST-TRANSITION DUMP ---
        post_dump_path = None
        post_dump_bytes = 0

        if self.enable_dumps:
            post_label = f"post_{new_state.value.lower()}"
            print(f"[STATE_MACHINE] 📸 Post-transition dump: {post_label}")

            try:
                if self.dump_type == "keys" and key_addresses:
                    post_dump_path, post_dump_bytes, _ = ssh_memory_dump.dump_key_regions(
                        self.process, key_addresses, self.output_dir, post_label, timestamp
                    )
                else:
                    # Always use simple dump_process_memory() (works reliably)
                    # The complex dump_heap_regions() hybrid approach has issues
                    post_dump_path, post_dump_bytes, _ = ssh_memory_dump.dump_process_memory(
                        self.process, self.output_dir, post_label, timestamp
                    )
            except Exception as e:
                print(f"[STATE_MACHINE] ⚠️  Post-dump failed: {e}")

        # --- LOG TRANSITION ---
        transition_data = {
            "old_state": old_state.value,
            "new_state": new_state.value,
            "timestamp": timestamp,
            "pre_dump": {
                "path": pre_dump_path,
                "bytes": pre_dump_bytes
            },
            "post_dump": {
                "path": post_dump_path,
                "bytes": post_dump_bytes
            }
        }

        if metadata:
            transition_data["metadata"] = metadata

        self.transition_log.append(transition_data)
        self._log_event("STATE_TRANSITION", transition_data)

        print(f"[STATE_MACHINE] ✓ Transition complete - Now: {new_state.value}")

        return True

    def quick_transition(self, new_state, metadata=None):
        """
        Transition without dumps (for testing or lightweight mode).

        Args:
            new_state (SSHState): Target state
            metadata (dict, optional): Additional metadata

        Returns:
            bool: True if transition succeeded
        """
        if not isinstance(new_state, SSHState):
            print(f"[STATE_MACHINE] ✗ Invalid state: {new_state}")
            return False

        old_state = self.current_state
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        self.current_state = new_state
        self.state_history.append((new_state, timestamp))

        transition_data = {
            "old_state": old_state.value,
            "new_state": new_state.value,
            "timestamp": timestamp,
            "mode": "quick"
        }

        if metadata:
            transition_data["metadata"] = metadata

        self.transition_log.append(transition_data)
        self._log_event("STATE_QUICK_TRANSITION", transition_data)

        print(f"[STATE_MACHINE] {old_state.value} → {new_state.value} (quick)")

        return True

    def log_event(self, event_type, data=None):
        """
        Log an arbitrary event (without state change).

        Args:
            event_type (str): Event type identifier
            data (dict, optional): Event data
        """
        self._log_event(event_type, data)

    def _log_event(self, event_type, data=None):
        """
        Internal event logger - writes to JSONL file.

        Args:
            event_type (str): Event type
            data (dict, optional): Event data
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "current_state": self.current_state.value,
            "pid": self.process.GetProcessID()
        }

        if data:
            event["data"] = data

        try:
            with open(self.event_log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[STATE_MACHINE] ⚠️  Event log write failed: {e}")

    def get_state(self):
        """Get current state"""
        return self.current_state

    def is_state(self, state):
        """Check if in specific state"""
        return self.current_state == state

    def get_history(self):
        """Get state history"""
        return self.state_history.copy()

    def get_transitions(self):
        """Get transition log"""
        return self.transition_log.copy()

    def dump_now(self, label, metadata=None, key_addresses=None):
        """
        Manual dump trigger (outside state transitions).

        Args:
            label (str): Dump label
            metadata (dict, optional): Additional metadata
            key_addresses (list, optional): For targeted dumps

        Returns:
            tuple: (dump_path, bytes_written)
        """
        if not self.enable_dumps:
            print("[STATE_MACHINE] Dumps disabled")
            return (None, 0)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        try:
            if self.dump_type == "keys" and key_addresses:
                dump_path, bytes_written, _ = ssh_memory_dump.dump_key_regions(
                    self.process, key_addresses, self.output_dir, label, timestamp
                )
            else:
                # Always use simple dump_process_memory() (works reliably)
                # The complex dump_heap_regions() hybrid approach has issues
                dump_path, bytes_written, _ = ssh_memory_dump.dump_process_memory(
                    self.process, self.output_dir, label, timestamp
                )

            self._log_event("MANUAL_DUMP", {
                "label": label,
                "dump_path": dump_path,
                "bytes": bytes_written,
                "metadata": metadata
            })

            return (dump_path, bytes_written)

        except Exception as e:
            print(f"[STATE_MACHINE] ✗ Manual dump failed: {e}")
            return (None, 0)

    def summary(self):
        """Print state machine summary"""
        print("\n" + "="*70)
        print("  SSH STATE MACHINE SUMMARY")
        print("="*70)
        print(f"Current State:  {self.current_state.value}")
        print(f"Output Dir:     {self.output_dir}")
        print(f"Event Log:      {self.event_log_path}")
        print(f"Transitions:    {len(self.transition_log)}")
        print(f"Dumps Enabled:  {self.enable_dumps}")
        print(f"Dump Type:      {self.dump_type}")
        print("")

        if self.state_history:
            print("State History:")
            for i, (state, ts) in enumerate(self.state_history):
                print(f"  {i+1}. {state.value} @ {ts}")

        print("="*70 + "\n")


# Convenience function for quick state machine creation
def create_state_machine(process, output_dir, dump_type="full", enable_dumps=True):
    """
    Factory function to create and initialize a state machine.

    Args:
        process (lldb.SBProcess): LLDB process to monitor
        output_dir (str): Output directory
        dump_type (str): "full", "heap", or "keys"
        enable_dumps (bool): Enable/disable dumps

    Returns:
        SSHStateMachine: Initialized state machine
    """
    return SSHStateMachine(process, output_dir, dump_type, enable_dumps)


# Example usage (for documentation)
"""
import ssh_state_machine

# Create state machine
sm = ssh_state_machine.create_state_machine(
    process, "/data/dumps", dump_type="heap", enable_dumps=True
)

# Track SSH lifecycle
sm.transition(ssh_state_machine.SSHState.KEX_COMPLETE,
              metadata={"kex_algorithm": "curve25519-sha256"})

sm.transition(ssh_state_machine.SSHState.ACTIVE,
              metadata={"cipher": "chacha20-poly1305@openssh.com"})

# Rekey scenario
sm.transition(ssh_state_machine.SSHState.REKEY_START)
sm.transition(ssh_state_machine.SSHState.REKEY_COMPLETE,
              metadata={"rekey_count": 2})

# Session close
sm.transition(ssh_state_machine.SSHState.SESSION_CLOSED)
sm.transition(ssh_state_machine.SSHState.CLEANUP)

# Manual dump at any time
sm.dump_now("custom_checkpoint", metadata={"reason": "investigating anomaly"})

# Get summary
sm.summary()
"""
