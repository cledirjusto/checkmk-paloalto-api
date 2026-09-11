#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Server-side calls: build the command line for agent_paloalto_api."""

from collections.abc import Iterator, Sequence

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)
from pydantic import BaseModel


class Params(BaseModel):
    api_key: Secret
    address: str | None = None
    port: int = 443
    verify_cert: bool = True
    timeout: float = 30.0
    sections: Sequence[str] | None = None
    public_ip_networks: Sequence[str] = ()
    config_cache_age: float | None = None


def _commands(params: Params, host_config: HostConfig) -> Iterator[SpecialAgentCommand]:
    if params.address:
        address = params.address
    elif host_config.primary_ip_config and host_config.primary_ip_config.address:
        address = host_config.primary_ip_config.address
    else:
        address = host_config.name

    args: list[str | Secret] = [
        "--host",
        address,
        "--port",
        str(params.port),
        "--timeout",
        str(params.timeout),
        # A bare Secret is rendered by Checkmk as "<id>:<password-store-path>",
        # so the key never appears on the command line.
        "--api-key-id",
        params.api_key,
    ]
    if not params.verify_cert:
        args.append("--no-cert-check")
    if params.config_cache_age:
        args += ["--config-cache-age", str(params.config_cache_age)]
    if params.sections:
        args += ["--sections", ",".join(params.sections)]
    for network in params.public_ip_networks:
        args += ["--public-ip-network", network]

    yield SpecialAgentCommand(command_arguments=args)


special_agent_paloalto_api = SpecialAgentConfig(
    name="paloalto_api",
    parameter_parser=Params.model_validate,
    commands_function=_commands,
)
