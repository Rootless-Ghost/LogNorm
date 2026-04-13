"""
LogNorm adapters package.

Each adapter handles one log source type and normalizes raw input
to ECS-lite event dicts.  Import the registry from this module to
look up an adapter by source_type key.
"""

from adapters.sysmon import SysmonAdapter
from adapters.wel import WELAdapter
from adapters.wazuh import WazuhAdapter
from adapters.syslog import SyslogAdapter
from adapters.cef import CEFAdapter

# Registry maps source_type string → adapter class
ADAPTER_REGISTRY: dict = {
    "sysmon":  SysmonAdapter,
    "wel":     WELAdapter,
    "wazuh":   WazuhAdapter,
    "syslog":  SyslogAdapter,
    "cef":     CEFAdapter,
}

SUPPORTED_SOURCES = list(ADAPTER_REGISTRY.keys())


def get_adapter(source_type: str):
    """Return an instantiated adapter for the given source_type, or None."""
    cls = ADAPTER_REGISTRY.get(source_type.lower())
    return cls() if cls else None
