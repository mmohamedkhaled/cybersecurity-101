"""IPv4 subnet planner.

Computes aligned network/broadcast boundaries for a single subnet from a host
count and allocates a sequence of non-overlapping subnets across named
locations.
"""

import ipaddress
import math
from typing import TypedDict

IPV4_BITS = 32
RESERVED_ADDRESSES = 2

# Structured return type of subnet_info. Keys contain spaces, so the functional
# TypedDict syntax is required.
SubnetInfo = TypedDict(
    "SubnetInfo",
    {
        "Network address": str,
        "CIDR": str,
        "CIDR subnet": str,
        "Broadcast address": str,
        "Ending IP": str,
        "Total IPs": int,
        "Usable IPs": int,
        "Usable range": str,
        "Next available start IP": str,
    },
)


def _subnet_params(host_count: int) -> tuple[int, int]:
    """Return the (CIDR prefix, total IP block size) for a host count.

    Args:
        host_count: Number of usable hosts the subnet must accommodate.

    Returns:
        A tuple ``(cidr, block_size)``.

    Raises:
        ValueError: If ``host_count`` is not positive or exceeds the IPv4 range.
    """
    if host_count <= 0:
        raise ValueError(f"host_count must be positive, got {host_count}.")
    total = host_count + RESERVED_ADDRESSES
    if total > 2 ** IPV4_BITS:
        raise ValueError("host_count exceeds the IPv4 address space.")

    bits = math.ceil(math.log2(total))
    return IPV4_BITS - bits, 2 ** bits


def subnet_info(start_ip: str, host_count: int) -> SubnetInfo:
    """Compute full boundary info for one subnet that fits ``host_count`` hosts.

    Aligns ``start_ip`` up to the correct CIDR boundary and returns the
    network/broadcast addresses, usable range, total IPs and the next available
    start IP.

    Args:
        start_ip: Starting IPv4 address as a dotted-quad string.
        host_count: Number of usable hosts the subnet must accommodate.

    Returns:
        A dict with keys ``Network address``, ``CIDR``, ``CIDR subnet``,
        ``Broadcast address``, ``Ending IP``, ``Total IPs``, ``Usable IPs``,
        ``Usable range`` and ``Next available start IP``.

    Raises:
        ValueError: If ``start_ip`` is not a valid IPv4 address or
            ``host_count`` is invalid.
    """
    cidr, block = _subnet_params(host_count)
    try:
        start_int = int(ipaddress.IPv4Address(start_ip))
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {start_ip!r}") from exc

    aligned = (start_int + block - 1) // block * block
    max_ipv4 = 2 ** IPV4_BITS - 1
    if aligned + block - 1 > max_ipv4:
        raise ValueError("subnet extends beyond the IPv4 address space")
    net = ipaddress.IPv4Address(aligned)
    broadcast = ipaddress.IPv4Address(aligned + block - 1)
    next_start_int = aligned + block
    next_start = (
        str(ipaddress.IPv4Address(next_start_int))
        if next_start_int <= max_ipv4
        else "(address space exhausted)"
    )

    return {
        'Network address': str(net),
        'CIDR': f'/{cidr}',
        'CIDR subnet': f'{net}/{cidr}',
        'Broadcast address': str(broadcast),
        'Ending IP': str(broadcast),
        'Total IPs': block,
        'Usable IPs': block - RESERVED_ADDRESSES,
        'Usable range': (
            f'{ipaddress.IPv4Address(aligned + 1)}'
            f' \u2013 {ipaddress.IPv4Address(aligned + block - 2)}'
        ),
        'Next available start IP': next_start,
    }


def allocate_subnets(
    start_ip: str,
    locations: list[tuple[str, int]] | dict[str, int],
) -> dict[str, str]:
    """Allocate consecutive, non-overlapping subnets across multiple locations.

    Args:
        start_ip: Starting IPv4 address for the first subnet.
        locations: A list of ``(name, host_count)`` tuples or a dict
            ``{name: host_count}``.

    Returns:
        A dict mapping each location name to ``"network/cidr"``.

    Raises:
        ValueError: If ``locations`` is empty, ``start_ip`` is invalid, or any
            ``host_count`` is invalid.
    """
    if isinstance(locations, dict):
        locations = list(locations.items())
    if not locations:
        raise ValueError("locations must not be empty.")

    try:
        ipaddress.IPv4Address(start_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {start_ip!r}") from exc

    current = ipaddress.IPv4Address(start_ip)
    result: dict[str, str] = {}
    for name, host_count in locations:
        info = subnet_info(str(current), host_count)
        result[name] = info['CIDR subnet']
        current = ipaddress.IPv4Address(
            int(ipaddress.IPv4Address(info['Network address'])) + info['Total IPs']
        )
    return result


def run_tests() -> None:
    """Run inline sanity checks for the subnet planner."""
    info = subnet_info("192.100.0.0", 1000)
    assert info['Network address'] == "192.100.0.0"
    assert info['CIDR'] == "/22"
    assert info['CIDR subnet'] == "192.100.0.0/22"
    assert info['Total IPs'] == 1024
    assert info['Usable IPs'] == 1022
    assert info['Broadcast address'] == "192.100.3.255"
    assert info['Next available start IP'] == "192.100.4.0"

    aligned = subnet_info("192.100.0.255", 1000)
    assert aligned['Network address'] == "192.100.4.0"

    full = subnet_info("0.0.0.0", 2 ** IPV4_BITS - 2)
    assert full['CIDR'] == "/0"
    assert full['Network address'] == "0.0.0.0"
    assert full['Broadcast address'] == "255.255.255.255"
    assert full['Next available start IP'] == "(address space exhausted)"

    try:
        subnet_info("255.255.255.255", 2)
        raise AssertionError("expected ValueError for subnet beyond IPv4 space")
    except ValueError:
        pass

    allocated = allocate_subnets(
        "192.100.0.0", [("Orlando", 4000), ("Chicago", 2000), ("LA", 8000)]
    )
    assert allocated["Orlando"] == "192.100.0.0/20"
    assert allocated["Chicago"] == "192.100.16.0/21"
    assert allocated["LA"] == "192.100.32.0/19"

    allocated_dict = allocate_subnets("192.100.0.0", {"Orlando": 4000})
    assert allocated_dict["Orlando"] == "192.100.0.0/20"

    try:
        subnet_info("192.100.0.0", 0)
        raise AssertionError("expected ValueError for host_count <= 0")
    except ValueError:
        pass

    try:
        subnet_info("not-an-ip", 1000)
        raise AssertionError("expected ValueError for invalid ip")
    except ValueError:
        pass

    try:
        allocate_subnets("192.100.0.0", [])
        raise AssertionError("expected ValueError for empty locations")
    except ValueError:
        pass

    print("All subnet tests passed.")


if __name__ == "__main__":
    print("Single subnet for 5000 hosts from 192.200.15.255:")
    for key, value in subnet_info("192.200.15.255", 5000).items():
        print(f"  {key}: {value}")

    print("\nAllocating subnets for multiple locations:")
    for loc, cidr in allocate_subnets(
        "192.100.0.0", [("Orlando", 4000), ("Chicago", 2000), ("LA", 8000)]
    ).items():
        print(f"  {loc}: {cidr}")

    print()
    run_tests()
