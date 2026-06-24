"""TCP and DNS utility helpers.

A collection of small, dependency-free helpers that compute common TCP/NAT/DNS
values used in network-security exercises: header sizing, handshake sequence
numbers, port classification, NAT port allocation, DNS birthday-attack odds,
TTL expiry and resolution hop counting.
"""

from datetime import datetime, timedelta

BYTES_PER_HEADER_WORD = 4
WELL_KNOWN_PORT_MAX = 1023
REGISTERED_PORT_MAX = 49151
DYNAMIC_PORT_MAX = 65535
DEFAULT_NAT_START_PORT = 49152
DNS_SOURCE_PORT_SPACE = 65536
TIME_FORMAT = "%H:%M"


def calculate_tcp_header_size(data_offset: int) -> int:
    """Return the TCP header size in bytes for a given data-offset field.

    Args:
        data_offset: The 4-bit data-offset value (number of 32-bit words).

    Returns:
        Header size in bytes.

    Raises:
        ValueError: If ``data_offset`` is outside the valid 4-bit range (0-15).
    """
    if not 0 <= data_offset <= 15:
        raise ValueError(
            f"data_offset must be in 0..15, got {data_offset}."
        )
    return data_offset * BYTES_PER_HEADER_WORD


def calculate_handshake_values(
    client_seq: int, server_seq: int
) -> dict[str, dict[str, int]]:
    """Return the SYN-ACK and final ACK values of a TCP three-way handshake.

    Args:
        client_seq: Initial sequence number chosen by the client.
        server_seq: Initial sequence number chosen by the server.

    Returns:
        A dict with ``Server_SYN-ACK`` and ``Client_ACK`` entries, each holding
        ``Seq`` and ``Ack`` values.

    Raises:
        ValueError: If either sequence number is negative.
    """
    if client_seq < 0 or server_seq < 0:
        raise ValueError("Sequence numbers must be non-negative.")
    return {
        "Server_SYN-ACK": {"Seq": server_seq, "Ack": client_seq + 1},
        "Client_ACK": {"Seq": client_seq + 1, "Ack": server_seq + 1},
    }


def classify_port(port: int) -> str:
    """Classify a TCP/UDP port into its IANA registry band.

    Args:
        port: Port number to classify.

    Returns:
        ``"Well-known port"`` (0-1023), ``"Registered port"`` (1024-49151) or
        ``"Dynamic/private port"`` (49152-65535).

    Raises:
        ValueError: If ``port`` is outside the range 0-65535.
    """
    if not 0 <= port <= DYNAMIC_PORT_MAX:
        raise ValueError(f"port must be in 0..{DYNAMIC_PORT_MAX}, got {port}.")
    if port <= WELL_KNOWN_PORT_MAX:
        return "Well-known port"
    if port <= REGISTERED_PORT_MAX:
        return "Registered port"
    return "Dynamic/private port"


def suggest_next_nat_port(
    used_ports: list[int], starting_port: int = DEFAULT_NAT_START_PORT
) -> int | None:
    """Return the lowest free private port at or above ``starting_port``.

    Args:
        used_ports: Ports already in use.
        starting_port: Lowest candidate port (defaults to 49152).

    Returns:
        The first available port, or None if the whole range is occupied.

    Raises:
        ValueError: If ``starting_port`` is outside 0-65535.
    """
    if not 0 <= starting_port <= DYNAMIC_PORT_MAX:
        raise ValueError(
            f"starting_port must be in 0..{DYNAMIC_PORT_MAX}, got {starting_port}."
        )
    used_set = set(used_ports)
    for port in range(starting_port, DYNAMIC_PORT_MAX + 1):
        if port not in used_set:
            return port
    return None


def dns_birthday_attack_success(n: int) -> float:
    """Approximate the success probability of a DNS birthday attack.

    Args:
        n: Number of queries and forged responses sent by the attacker.

    Returns:
        Probability in the range 0..1.

    Raises:
        ValueError: If ``n`` is not positive.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}.")
    return 1 - pow((1 - n / DNS_SOURCE_PORT_SPACE), n)


def calculate_expiration_time(
    cached_time_str: str, ttl_seconds: int
) -> str:
    """Return the ``HH:MM`` time at which a cached DNS entry expires.

    Args:
        cached_time_str: Cache time as a ``HH:MM`` string (24-hour clock).
        ttl_seconds: Time-to-live in seconds.

    Returns:
        Expiration time formatted as ``HH:MM``.

    Raises:
        ValueError: If ``cached_time_str`` is not a valid ``HH:MM`` time or
            ``ttl_seconds`` is negative.
    """
    if ttl_seconds < 0:
        raise ValueError(f"ttl_seconds must be non-negative, got {ttl_seconds}.")
    try:
        cached_time = datetime.strptime(cached_time_str, TIME_FORMAT)
    except ValueError as exc:
        raise ValueError(
            f"cached_time_str must match {TIME_FORMAT}: {cached_time_str!r}"
        ) from exc
    expiration_time = cached_time + timedelta(seconds=ttl_seconds)
    return expiration_time.strftime(TIME_FORMAT)


def count_dns_hops(domain: str) -> int:
    """Return the number of resolution hops for a fully-qualified domain.

    The hop count is the number of dot-separated labels (e.g. ``cs.ucf.edu`` has
    three labels and therefore three hops).

    Args:
        domain: The domain name to inspect.

    Returns:
        Number of labels/hops.

    Raises:
        ValueError: If ``domain`` is empty or only whitespace.
    """
    stripped = domain.strip()
    if not stripped:
        raise ValueError("domain must not be empty.")
    return stripped.count('.') + 1


def run_tests() -> None:
    """Run inline sanity checks for the TCP/DNS helpers."""
    assert calculate_tcp_header_size(6) == 24
    assert calculate_tcp_header_size(5) == 20
    assert calculate_tcp_header_size(15) == 60

    handshake = calculate_handshake_values(42, 5000)
    assert handshake["Server_SYN-ACK"] == {"Seq": 5000, "Ack": 43}
    assert handshake["Client_ACK"] == {"Seq": 43, "Ack": 5001}

    assert classify_port(80) == "Well-known port"
    assert classify_port(8080) == "Registered port"
    assert classify_port(50000) == "Dynamic/private port"
    assert classify_port(0) == "Well-known port"
    assert classify_port(DYNAMIC_PORT_MAX) == "Dynamic/private port"

    assert suggest_next_nat_port([50001, 50002]) == DEFAULT_NAT_START_PORT
    assert suggest_next_nat_port([49152, 49153, 49155]) == 49154
    assert suggest_next_nat_port(list(range(49152, 65536))) is None

    assert 0.0 <= dns_birthday_attack_success(213) <= 1.0
    assert dns_birthday_attack_success(1) > 0.0

    assert calculate_expiration_time("14:45", 1800) == "15:15"
    assert calculate_expiration_time("23:59", 60) == "00:00"

    assert count_dns_hops("cs.ucf.edu") == 3
    assert count_dns_hops("example.com") == 2
    assert count_dns_hops("localhost") == 1

    try:
        classify_port(70000)
        raise AssertionError("expected ValueError for invalid port")
    except ValueError:
        pass

    try:
        calculate_tcp_header_size(16)
        raise AssertionError("expected ValueError for invalid data_offset")
    except ValueError:
        pass

    try:
        calculate_expiration_time("25:99", 1800)
        raise AssertionError("expected ValueError for invalid time")
    except ValueError:
        pass

    try:
        count_dns_hops("   ")
        raise AssertionError("expected ValueError for empty domain")
    except ValueError:
        pass

    print("All TCP tests passed.")


if __name__ == "__main__":
    print("TCP header size (offset = 6):", calculate_tcp_header_size(6), "bytes")
    print("Three-way handshake:", calculate_handshake_values(42, 5000))
    print("Port 8080 is a:", classify_port(8080))
    print("Next available NAT port:", suggest_next_nat_port([50001, 50002]))
    print(
        "DNS Birthday attack probability (n=213):",
        round(dns_birthday_attack_success(213) * 100, 2),
        "%",
    )
    print("TTL expires at:", calculate_expiration_time("14:45", 1800))
    print("Hops for cs.ucf.edu:", count_dns_hops("cs.ucf.edu"))
    print()
    run_tests()
