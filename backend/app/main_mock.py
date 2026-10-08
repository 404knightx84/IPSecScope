from schemas import AnalyzeResponse, Item, Score, Finding, Traffic, ThreatMatrix, ThreatEntry

def mock_response(name):
    items = [
        Item(id="ike_version", label="IKE version", value="IKEv2", status="observed", confidence=1.0, evidence=[1, 2]),
        Item(id="dh_group", label="DH group", value="MODP_2048", status="observed", confidence=1.0, evidence=[1, 2]),
        Item(id="cipher_family", label="Cipher family", value="AES-GCM", status="inferred", confidence=0.93),
        Item(id="tunnel_mode", label="Mode", status="not_determinable",
             reason="Traffic is fixed-size UDP with no TCP anchor",
             advisor="Capture some TCP traffic (web or file transfer) through the tunnel"),
        Item(id="pfs", label="PFS", status="not_determinable",
             reason="No child rekey seen in this capture",
             advisor="Capture longer than the child lifetime, or trigger a rekey on a gateway you own"),
        Item(id="key_size", label="Cipher key size", status="not_determinable",
             reason="Key length is not visible in ESP lengths",
             advisor="Read the key size from the gateway configuration (status: provided)"),
    ]
    return AnalyzeResponse(
        file=name, duration_s=112.4, ike_packets=14, esp_packets=11800, items=items,
        traffic=Traffic(status="inferred", value="voip", confidence=0.86,
                        probabilities={"email": 0.02, "ping": 0.02, "video": 0.05, "voip": 0.86, "web": 0.05},
                        windows=22, smoke_model=True, low_confidence=True,
                        reason="Preliminary model"),
        score=Score(score_min=70, score_max=88, risk_level="Medium", risk_level_best_case="Medium"),
        findings=[Finding(id="R04", title="No PFS evidenced", severity="Medium", status="not_determinable",
                          fix="Include a DH group in the child proposal", reference="RFC 8247")],
        threat_matrix=ThreatMatrix(likelihood_axis={"1": "Low", "2": "Medium", "3": "High"},
                                   impact_axis={"1": "Low", "2": "Medium", "3": "High"},
                                   cells={"2-3": [ThreatEntry(id="T3", name="Decryption through weak primitives", basis="found")]}),
        mock=True)
