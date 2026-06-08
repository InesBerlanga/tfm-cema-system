"""Ejemplo end-to-end: clasifica un evento ciber y un evento EW.

Ejecuta con:
    python example_classify.py

Asume que los endpoints LLM están corriendo (ver .env).
"""

from datetime import datetime, timezone
from pathlib import Path

from cyber_classifier import CyberClassifier
from ew_classifier import EwClassifier
from llm_client import get_llm
from schemas import RawCyberEvent, RawEwEvent


HERE = Path(__file__).parent
KNOWLEDGE = HERE / "knowledge"


def demo_cyber():
    print("\n" + "=" * 60)
    print("CLASIFICACIÓN CIBER")
    print("=" * 60)

    clf = CyberClassifier(
        llm=get_llm("gemma", temperature=0.1),
        catalog_path=KNOWLEDGE / "mitre_techniques.json",
    )

    event = RawCyberEvent(
        timestamp=datetime.now(timezone.utc),
        source="suricata-sensor-01",
        raw_text=(
            "ET TROJAN suspicious PowerShell encoded command executed on host "
            "WS-042. Process spawned by Outlook.exe after user opened attachment "
            "'invoice.docm'. Subsequent outbound connection to 185.x.x.x:443."
        ),
        src_ip="10.0.4.42",
        dst_ip="185.220.101.7",
        asset_id="WS-042",
        severity=4,
    )

    result = clf.classify(event)
    print(result.model_dump_json(indent=2))


def demo_ew():
    print("\n" + "=" * 60)
    print("CLASIFICACIÓN EW")
    print("=" * 60)

    clf = EwClassifier(
        llm=get_llm("gemma", temperature=0.1),
        catalog_path=KNOWLEDGE / "ew_techniques.json",
    )

    event = RawEwEvent(
        timestamp=datetime.now(timezone.utc),
        source="sdr-station-03",
        raw_description=(
            "Detected high-power broadband emission centered near 1575 MHz "
            "covering ~50 MHz around GPS L1 band. Signal characteristics consistent "
            "with intentional noise injection. GPS receivers in the area report "
            "loss of lock."
        ),
        freq_center_mhz=1575.42,
        bandwidth_khz=50000,
        power_dbm=-30,
        doa_deg=127.5,
        location=(40.4168, -3.7038),
        asset_id="GPS-RX-12",
    )

    result = clf.classify(event)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    demo_ew()
    demo_cyber()
    
