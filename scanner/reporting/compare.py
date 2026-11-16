"""Scan-to-scan comparison with explanations that separate observation / probable explanation / hypothesis."""


def _index(store, sid):
    return {(p["host"], p["proto"], p["port"]): p for p in store.ports(sid)}


def compare(store, a_id, b_id):
    a, b = _index(store, a_id), _index(store, b_id)
    sa, sb = store.get_scan(a_id), store.get_scan(b_id)
    changes = []
    for k in sorted(set(a) | set(b)):
        pa, pb = a.get(k), b.get(k)
        old, new = (pa["state"] if pa else "absent"), (pb["state"] if pb else "absent")
        if old != new:
            changes.append({"host": k[0], "proto": k[1], "port": k[2], "from": old, "to": new,
                            "service": (pb or pa).get("service", "")})
    newly_exposed = [c for c in changes if c["to"] == "open" and c["from"] in ("absent", "closed", "filtered")]
    notes = []
    by_host = {}
    for c in changes:
        by_host.setdefault(c["host"], []).append(c)
    for h, cs in by_host.items():
        went_filtered = [c for c in cs if c["from"] == "open" and c["to"] == "filtered"]
        stayed_open = [k for k, p in b.items() if k[0] == h and p["state"] == "open" and a.get(k, {}).get("state") == "open"]
        if len(went_filtered) >= 2:
            ports = ", ".join(f"{c['proto']}/{c['port']}" for c in went_filtered)
            note = {"host": h, "observed": f"{len(went_filtered)} ports changed open -> filtered together: {ports}",
                    "probable": "a firewall or access-control change took effect between the scans",
                    "hypotheses": ["temporary blocking of the scanner (would typically also affect services that stayed open, "
                                   + ("which it did not" if stayed_open else "none stayed open, so this fits") + ")",
                                   "a rate-limit or knock-based policy hiding services"]}
            notes.append(note)
        opened = [c for c in cs if c["to"] == "open" and c["from"] != "open"]
        if opened:
            notes.append({"host": h, "observed": "newly open: " + ", ".join(f"{c['proto']}/{c['port']}" for c in opened),
                          "probable": "new exposure or a service that became reachable (e.g. after an access-control change)",
                          "hypotheses": []})
    if sa and sb and sa["vantage"] != sb["vantage"]:
        notes.append({"host": "*", "observed": f"scans used different vantage points ({sa['vantage']} vs {sb['vantage']})",
                      "probable": "differences may reflect network segmentation rather than host changes", "hypotheses": []})
    return {"a": a_id, "b": b_id, "changes": changes, "newly_exposed": newly_exposed, "notes": notes,
            "unchanged": sum(1 for k in a if k in b and a[k]["state"] == b[k]["state"])}
