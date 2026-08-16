from __future__ import annotations

from agent.policy import PolicyDecision, PolicyEngine
from agent.profiler import DeviceProfile


def test_hdd_default_policy_selects_hdd_overwrite():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", rotational=True, capabilities={})

    decision = engine.decide(profile)

    assert decision.selected_pathway == "HDD_OVERWRITE"
    assert decision.device_type == "HDD"
    assert decision.unsupported is False


def test_hdd_ata_erase_supported_but_default_policy_keeps_hdd_overwrite():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/sdb",
        device_type="HDD",
        rotational=True,
        capabilities={"security": {"supported": True, "frozen": False}},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "HDD_OVERWRITE"
    assert decision.reason.startswith("Default HDD policy")


def test_hdd_ata_erase_explicit_and_not_frozen_selects_ata_erase():
    engine = PolicyEngine(policy="ATA_ERASE")
    profile = DeviceProfile(
        device_path="/dev/sdc",
        device_type="HDD",
        rotational=True,
        capabilities={"security": {"supported": True, "frozen": False}},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "ATA_ERASE"
    assert decision.reason.startswith("HDD has ATA security capability")


def test_hdd_ata_erase_selected_but_frozen_is_unsupported():
    engine = PolicyEngine(policy="ATA_ERASE")
    profile = DeviceProfile(
        device_path="/dev/sdd",
        device_type="HDD",
        rotational=True,
        capabilities={"security": {"supported": True, "frozen": True}},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway is None
    assert decision.unsupported is True
    assert "frozen" in decision.reason.lower()


def test_sata_ssd_with_crypto_applicable_selects_crypto_erase():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/sde",
        device_type="SATA SSD",
        rotational=False,
        capabilities={
            "crypto_erase_supported": True,
            "crypto_erase_applicable": True,
        },
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "CRYPTO_ERASE"
    assert decision.unsupported is False


def test_sata_ssd_without_crypto_but_with_other_supported_device_method_selects_method():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/sdf",
        device_type="SATA SSD",
        rotational=False,
        capabilities={"secure_erase_supported": True},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "ATA_ERASE"
    assert decision.unsupported is False


def test_sata_ssd_without_acceptable_device_method_is_unsupported():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/sdg",
        device_type="SATA SSD",
        rotational=False,
        capabilities={},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway is None
    assert decision.unsupported is True
    assert "manual" in decision.reason.lower()


def test_sata_ssd_must_not_select_hdd_overwrite():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/sdh",
        device_type="SATA SSD",
        rotational=False,
        capabilities={"crypto_erase_supported": False},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway != "HDD_OVERWRITE"
    assert decision.selected_pathway is None or decision.selected_pathway == "ATA_ERASE"


def test_nvme_with_crypto_supported_and_applicable_selects_crypto_erase():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/nvme0n1",
        device_type="NVMe",
        capabilities={
            "sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": False},
            "crypto_erase_applicable": True,
        },
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "CRYPTO_ERASE"
    assert decision.unsupported is False


def test_nvme_without_crypto_but_with_block_erase_selects_block_erase():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/nvme1n1",
        device_type="NVMe",
        capabilities={
            "sanicap": {"crypto_erase": False, "block_erase": True, "overwrite": False},
        },
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "BLOCK_ERASE"
    assert decision.unsupported is False


def test_nvme_with_no_acceptable_sanitization_capability_is_unsupported():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/nvme2n1",
        device_type="NVMe",
        capabilities={"sanicap": {"crypto_erase": False, "block_erase": False, "overwrite": False}},
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway is None
    assert decision.unsupported is True


def test_nvme_sanicap_bit_mapping_is_respected():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/nvme3n1",
        device_type="NVMe",
        capabilities={
            "sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
            "crypto_erase_applicable": True,
        },
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "CRYPTO_ERASE"
    assert "CRYPTO_ERASE" in decision.supported_methods
    assert "BLOCK_ERASE" in decision.supported_methods


def test_missing_capability_information_is_conservative():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(device_path="/dev/sdi", device_type="SATA SSD", rotational=False, capabilities={})

    decision = engine.decide(profile)

    assert decision.selected_pathway is None
    assert decision.unsupported is True
    assert decision.warnings


def test_unknown_device_type_is_unsupported():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(device_path="/dev/ram0", device_type="UNKNOWN", capabilities={})

    decision = engine.decide(profile)

    assert decision.selected_pathway is None
    assert decision.unsupported is True


def test_policy_decision_should_not_execute_destructive_command():
    engine = PolicyEngine(policy="default")
    profile = DeviceProfile(
        device_path="/dev/nvme4n1",
        device_type="NVMe",
        capabilities={
            "sanicap": {"crypto_erase": True, "block_erase": False, "overwrite": False},
            "crypto_erase_applicable": True,
        },
    )

    decision = engine.decide(profile)

    assert decision.selected_pathway == "CRYPTO_ERASE"
    assert hasattr(decision, "selected_pathway")
    assert decision.metadata["capabilities"]["sanicap"]["crypto_erase"] is True
