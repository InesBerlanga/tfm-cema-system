"""Ejemplo end-to-end: clasifica un evento ciber (ECS) y uno EW.

Construye los eventos con la estructura anidada real que asumimos a la
entrada del sistema. Los Pydantic models validan el formato.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys


_ROOT = Path(__file__).parent.parent  # tests/ -> repo root
sys.path.insert(0, str(_ROOT / 'src' / 'modules'))
sys.path.insert(0, str(_ROOT / 'src'))
from cyber_classifier import CyberClassifier
from ew_classifier import EwClassifier
from llm_client import get_llm
from schemas import (
    ECSEndpoint,
    ECSEvent,
    ECSHost,
    ECSRule,
    EwDetectionInfo,
    EwSensorInfo,
    EwSignalInfo,
    RawCyberEvent,
    RawEwEvent,
)


HERE = Path(__file__).parent.parent
KNOWLEDGE = HERE / "knowledge"


def demo_cyber():
    print("\n" + "=" * 60)
    print("CLASIFICACIÓN CIBER (entrada ECS)")
    print("=" * 60)

    clf = CyberClassifier(
        llm=get_llm("gpt", temperature=0.1),
        catalog_path=KNOWLEDGE / "mitre_techniques.json",
    )

    # Equivalente a un JSON ECS que llegase de Suricata, montado como
    # objeto Pydantic. En producción harías RawCyberEvent.model_validate(json_data).
    event = RawCyberEvent(
        timestamp=datetime.now(timezone.utc),
        event=ECSEvent(
            kind="alert",
            category=["intrusion_detection", "network"],
            severity=4,
            module="suricata",
            dataset="suricata.alert",
        ),
        source=ECSEndpoint(ip="10.0.4.42", port=49234),
        destination=ECSEndpoint(ip="185.220.101.7", port=443),
        host=ECSHost(name="WS-042"),
        rule=ECSRule(
            id="2027856",
            name="ET TROJAN suspicious PowerShell encoded outbound",
        ),
        user={"name": "alice"},
        process={"name": "powershell.exe", "parent": {"name": "outlook.exe"}},
        message=(
            "PowerShell encoded command executed on host WS-042. "
            "Process spawned by Outlook.exe after user opened attachment "
            "'invoice.docm'. Subsequent outbound connection to 185.220.101.7:443."
        ),
    )

    result = clf.classify(event)
    print(result.model_dump_json(indent=2))


def demo_ew():
    print("\n" + "=" * 60)
    print("CLASIFICACIÓN EW (sensor + signal + detection)")
    print("=" * 60)

    clf = EwClassifier(
        llm=get_llm("gpt", temperature=0.1),
        catalog_path=KNOWLEDGE / "ew_techniques.json",
    )

    event = RawEwEvent(
        id="ew-2026-06-16T10:15:21-gnss01",
        timestamp=datetime.now(timezone.utc),
        sensor=EwSensorInfo(
            id="GNSS-MON-01",
            type="gnss_rfi_monitor",
            lat=40.4168,
            lon=-3.7038,
        ),
        signal=EwSignalInfo(
            freq_mhz=1575.42,
            bw_mhz=4.0,
            power_dbm=-30.0,
            duration_s=43.0,
            doa_deg=127.5,
        ),
        # El alias "class" permite recibir JSON con {"class": "..."}
        detection=EwDetectionInfo(
            **{
                "class": "wideband_interference",
                "severity": "high",
                "affected_system": "GPS_L1",
                "summary": (
                    "Wideband interference detected over GPS L1, sustained 43 s, "
                    "C/N0 dropped 24 dB, multiple GPS receivers reported loss of lock."
                ),
            }
        ),
    )

    result = clf.classify(event)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    demo_ew()
    demo_cyber()