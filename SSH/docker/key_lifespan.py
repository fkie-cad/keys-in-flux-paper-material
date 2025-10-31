#!/usr/bin/env python3
"""
SSH Key Lifespan Tracking Data Structures

This module defines data structures for tracking the complete lifecycle
of SSH encryption keys from derivation to destruction.

Future Integration Points:
- Keylog parsing (current: openssh_groundtruth NEWKEYS format)
- PCAP correlation (future: match packets to keys)
- Memory tracking (future: LLDB integration for key destruction)

Author: SSH Key Lifecycle Lab
"""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime


@dataclass
class KeyLifespanEntry:
    """
    Complete key lifecycle tracking entry

    Tracks a single SSH encryption key through its entire lifecycle:
    1. Derivation (from KEX)
    2. First use (first encrypted packet)
    3. Active usage period
    4. Last use (last packet before rekey)
    5. Destruction (memory cleared)
    """

    # === Identity ===
    key_id: str                          # Unique identifier: f"{session}_{mode}_{seq}"
    server: str                          # Server implementation: openssh, dropbear, wolfssh, paramiko
    session_id: str                      # Session identifier (timestamp or connection ID)

    # === Timing (from groundtruth keylog) ===
    derived_at: float                    # Timestamp when key was derived (from NEWKEYS entry)
    mode: str                            # "IN" (server→client) or "OUT" (client→server)

    # === Packet Correlation (future: from PCAP analysis) ===
    first_packet_at: Optional[float] = None   # Timestamp of first encrypted packet with this key
    last_packet_at: Optional[float] = None    # Timestamp of last packet before new key
    packet_count: int = 0                     # Number of packets encrypted with this key
    bytes_encrypted: int = 0                  # Total bytes encrypted with this key

    # === Memory Tracking (future: LLDB integration) ===
    memory_cleared_at: Optional[float] = None  # When key was wiped from memory
    memory_address: Optional[str] = None       # Memory address where key was stored

    # === Key Metadata (from groundtruth) ===
    cipher: str = ""                     # Cipher algorithm: chacha20-poly1305, aes256-gcm, etc.
    key_hex: str = ""                    # Actual key value (hex encoded)
    key_length: int = 0                  # Key length in bytes
    iv_hex: str = ""                     # IV if available

    # === Rekey Context ===
    is_rekey: bool = False               # True if this key was derived during rekey
    previous_key_id: Optional[str] = None # Reference to previous key (for rekey)
    rekey_trigger: str = ""              # How rekey was triggered: client, server, automatic, data_threshold

    # === Computed Properties ===

    @property
    def creation_to_use_latency(self) -> Optional[float]:
        """
        Time from key derivation to first packet use
        Measure of KEX overhead
        """
        if self.first_packet_at:
            return self.first_packet_at - self.derived_at
        return None

    @property
    def active_lifespan(self) -> Optional[float]:
        """
        Time from first to last packet
        Measure of actual key usage period
        """
        if self.first_packet_at and self.last_packet_at:
            return self.last_packet_at - self.first_packet_at
        return None

    @property
    def total_lifespan(self) -> Optional[float]:
        """
        Time from derivation to memory clearing
        Complete key lifecycle duration
        """
        if self.memory_cleared_at:
            return self.memory_cleared_at - self.derived_at
        return None

    @property
    def memory_retention_time(self) -> Optional[float]:
        """
        Time key stayed in memory after last use
        Security metric: how long sensitive data persists
        """
        if self.last_packet_at and self.memory_cleared_at:
            return self.memory_cleared_at - self.last_packet_at
        return None

    @property
    def packets_per_second(self) -> Optional[float]:
        """Average packet rate during key usage"""
        if self.active_lifespan and self.active_lifespan > 0:
            return self.packet_count / self.active_lifespan
        return None

    @property
    def throughput_mbps(self) -> Optional[float]:
        """Average throughput in Mbps during key usage"""
        if self.active_lifespan and self.active_lifespan > 0:
            bits = self.bytes_encrypted * 8
            return (bits / self.active_lifespan) / 1_000_000
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'key_id': self.key_id,
            'server': self.server,
            'session_id': self.session_id,
            'derived_at': self.derived_at,
            'mode': self.mode,
            'first_packet_at': self.first_packet_at,
            'last_packet_at': self.last_packet_at,
            'memory_cleared_at': self.memory_cleared_at,
            'cipher': self.cipher,
            'key_hex': self.key_hex[:32] + '...' if len(self.key_hex) > 32 else self.key_hex,
            'is_rekey': self.is_rekey,
            'rekey_trigger': self.rekey_trigger,
            # Computed metrics
            'creation_to_use_latency': self.creation_to_use_latency,
            'active_lifespan': self.active_lifespan,
            'total_lifespan': self.total_lifespan,
            'memory_retention_time': self.memory_retention_time,
            'packet_count': self.packet_count,
            'bytes_encrypted': self.bytes_encrypted,
            'packets_per_second': self.packets_per_second,
            'throughput_mbps': self.throughput_mbps
        }


@dataclass
class SessionLifespan:
    """
    Tracks all keys for a single SSH session
    """
    session_id: str
    server: str
    started_at: float
    ended_at: Optional[float] = None
    keys: List[KeyLifespanEntry] = field(default_factory=list)
    rekey_count: int = 0

    @property
    def duration(self) -> Optional[float]:
        """Total session duration"""
        if self.ended_at:
            return self.ended_at - self.started_at
        return None

    @property
    def average_key_lifespan(self) -> Optional[float]:
        """Average lifespan across all keys"""
        lifespans = [k.total_lifespan for k in self.keys if k.total_lifespan]
        if lifespans:
            return sum(lifespans) / len(lifespans)
        return None

    def add_key(self, key: KeyLifespanEntry):
        """Add a key to this session"""
        self.keys.append(key)
        if key.is_rekey:
            self.rekey_count += 1

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'session_id': self.session_id,
            'server': self.server,
            'started_at': self.started_at,
            'ended_at': self.ended_at,
            'duration': self.duration,
            'rekey_count': self.rekey_count,
            'key_count': len(self.keys),
            'average_key_lifespan': self.average_key_lifespan,
            'keys': [k.to_dict() for k in self.keys]
        }


@dataclass
class ExperimentLifespanReport:
    """
    Complete lifespan report for all servers in an experiment
    """
    timestamp: str
    servers_tested: List[str]
    sessions: List[SessionLifespan] = field(default_factory=list)

    def add_session(self, session: SessionLifespan):
        """Add a session to the report"""
        self.sessions.append(session)

    def get_session_by_server(self, server: str) -> List[SessionLifespan]:
        """Get all sessions for a specific server"""
        return [s for s in self.sessions if s.server == server]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export"""
        return {
            'timestamp': self.timestamp,
            'servers_tested': self.servers_tested,
            'total_sessions': len(self.sessions),
            'total_keys_tracked': sum(len(s.keys) for s in self.sessions),
            'sessions': [s.to_dict() for s in self.sessions]
        }


# === Helper Functions ===

def create_key_id(session_id: str, mode: str, sequence: int) -> str:
    """Generate unique key ID"""
    return f"{session_id}_{mode}_{sequence}"


def parse_timestamp(timestamp_str: str) -> float:
    """Parse various timestamp formats to float"""
    try:
        # Try as unix timestamp
        return float(timestamp_str)
    except ValueError:
        # Try as ISO format
        dt = datetime.fromisoformat(timestamp_str)
        return dt.timestamp()


if __name__ == '__main__':
    # Example usage
    print("SSH Key Lifespan Tracking - Data Structures")
    print("=" * 60)

    # Create example key entry
    key = KeyLifespanEntry(
        key_id="1760378380_IN_0",
        server="openssh",
        session_id="1760378380",
        derived_at=1760378380.0,
        mode="IN",
        cipher="chacha20-poly1305@openssh.com",
        key_hex="a76d2323665bbecd331dc2b8cb099dfa...",
        key_length=64
    )

    # Simulate packet usage
    key.first_packet_at = 1760378380.5
    key.last_packet_at = 1760378385.5
    key.packet_count = 100
    key.bytes_encrypted = 1024 * 50  # 50KB

    # Simulate memory clearing
    key.memory_cleared_at = 1760378386.0

    print(f"\nExample Key Entry:")
    print(f"  Key ID: {key.key_id}")
    print(f"  Server: {key.server}")
    print(f"  Mode: {key.mode}")
    print(f"  Cipher: {key.cipher}")
    print(f"\nTiming Metrics:")
    print(f"  Creation→Use Latency: {key.creation_to_use_latency:.3f}s")
    print(f"  Active Lifespan: {key.active_lifespan:.3f}s")
    print(f"  Total Lifespan: {key.total_lifespan:.3f}s")
    print(f"  Memory Retention: {key.memory_retention_time:.3f}s")
    print(f"\nTraffic Metrics:")
    print(f"  Packets: {key.packet_count}")
    print(f"  Bytes: {key.bytes_encrypted}")
    print(f"  Packets/sec: {key.packets_per_second:.2f}")
    print(f"  Throughput: {key.throughput_mbps:.2f} Mbps")
