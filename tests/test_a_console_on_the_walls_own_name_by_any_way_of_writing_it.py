"""A console on a host name the wall is looked at under is told by its host whichever way it is written (the coordinator's
point after the round 5 review: security.shares_our_name).

The link's host and the Host header were compared as written: [0:0:0:0:0:0:0:1] was not [::1], and a host written as
numbers Python cannot read, 2130706433, which a browser takes for 127.0.0.1, was not 127.0.0.1. Both sides are now read
the way store.device_url writes a host (lower case, no dot at its end, numbers in their one form by ipaddress); a host that
looks like numbers and cannot be read so counts as the wall's own: no pass is made out to it.
"""

from __future__ import annotations

import pytest

from qkvm.security import shares_our_name


@pytest.mark.parametrize(
    ("link", "host"),
    [
        ("https://[0:0:0:0:0:0:0:1]:8443/", "[::1]:8787"),  # the link's host, written the long way
        ("http://2130706433:8443/", "127.0.0.1:8787"),  # numbers Python cannot read, which a browser takes for 127.0.0.1
        ("http://127.1:8443/", "127.0.0.1:8787"),
        ("http://0x7f.0.0.1:8443/", "127.0.0.1"),
        ("https://127.000.000.001:8443/", "127.0.0.1"),
        ("https://[::1]:8443/", "[0:0:0:0:0:0:0:1]:8787"),  # the Host header, written the long way
        ("https://127.0.0.1:8443/", "2130706433:8787"),  # the Host header, numbers Python cannot read
        ("https://WALL.lan.:8443/", "wall.LAN:8787"),
    ],
)
def test_a_link_on_the_walls_own_host_by_any_way_of_writing_it_shares_its_name(link: str, host: str) -> None:
    assert shares_our_name(link, host), (link, host)


def test_a_name_it_was_given_for_itself_is_read_the_same_way() -> None:
    assert shares_our_name("https://[::1]:8443/", "wall.lan", ["0:0:0:0:0:0:0:1"])
    assert shares_our_name("https://WALL.example.com.:8443/", "10.0.0.5", ["wall.example.COM"])


@pytest.mark.parametrize(
    ("link", "host"),
    [
        ("https://127.0.0.1:8443/", "[::1]:8787"),
        ("https://192.168.1.20/", "wall.lan:8787"),
        ("https://kvm.lan/", "wall.lan"),
        ("https://[::2]/", "[0:0:0:0:0:0:0:1]"),
    ],
)
def test_another_host_does_not(link: str, host: str) -> None:
    assert not shares_our_name(link, host), (link, host)
