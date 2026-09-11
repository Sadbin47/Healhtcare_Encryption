"""Run the deployable healthcare API from environment-provided configuration.

This launcher binds the API to the configured interface and keeps all runtime
state outside the source tree. TLS termination is deployment-specific and is
intentionally not implemented here.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from api import HealthcareAPI, create_server  # noqa: E402
from audit import JsonlAuditSink  # noqa: E402
from auth import TokenAuthenticator  # noqa: E402
from blockchain_client import BlockchainClient  # noqa: E402
from database import Database  # noqa: E402
from service import HealthcareWorkflowService  # noqa: E402
from storage.local_storage import LocalStorage  # noqa: E402


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def build_server():
    database = Database(os.environ.get("HEALTHCARE_DB_PATH", "/var/lib/healthcare/metadata.sqlite3"))
    storage = LocalStorage(os.environ.get("HEALTHCARE_STORAGE_ROOT", "/var/lib/healthcare/envelopes"))
    blockchain = BlockchainClient(
        provider_url=_required("HEALTHCARE_RPC_URL"),
        contract_address=_required("HEALTHCARE_CONTRACT_ADDRESS"),
        private_key=_required("HEALTHCARE_PRIVATE_KEY"),
    )
    doctor_addresses = json.loads(os.environ.get("HEALTHCARE_DOCTOR_ADDRESSES", "{}"))
    if not isinstance(doctor_addresses, dict):
        raise RuntimeError("HEALTHCARE_DOCTOR_ADDRESSES must be a JSON object")
    audit = JsonlAuditSink(os.environ.get("HEALTHCARE_AUDIT_PATH", "/var/lib/healthcare/audit/events.jsonl"))
    service = HealthcareWorkflowService(
        database,
        storage,
        blockchain,
        doctor_addresses=doctor_addresses,
        registrar_address=os.environ.get("HEALTHCARE_REGISTRAR_ADDRESS") or None,
        audit_sink=audit,
    )
    authenticator = TokenAuthenticator.from_environment(_required("HEALTHCARE_TOKENS"))
    api = HealthcareAPI(service, authenticator=authenticator)
    server = create_server(
        os.environ.get("HEALTHCARE_BIND_HOST", "10.77.0.1"),
        int(os.environ.get("HEALTHCARE_PORT", "8443")),
        api,
        vpn_network=os.environ.get("HEALTHCARE_VPN_NETWORK", "10.77.0.0/24"),
        vpn_interface_address=os.environ.get("HEALTHCARE_VPN_INTERFACE", "10.77.0.1"),
    )
    server.database = database
    return server


def main() -> None:
    server = build_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.database.close()


if __name__ == "__main__":
    main()
