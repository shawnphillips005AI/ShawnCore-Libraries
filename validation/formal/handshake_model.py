#!/usr/bin/env python3
"""Bounded symbolic (Dolev-Yao) model of the authenticated handshake, protocol version 2.

This is NOT ProVerif or Tamarin, and it is not a proof of the protocol. It is a small, readable
model checker written for this repository because neither tool was available. It covers a fixed,
finite scenario (two key-generating sessions, five encapsulating sessions, one attacker identity),
so it says nothing about unbounded sessions, and it models cryptography as ideal (a free algebra):
it shows that the *message design* has no attack of the kinds listed below within that scenario,
not that ML-KEM, ML-DSA, HMAC or HKDF are secure.

Model
-----
Terms are nested tuples. The attacker controls the network and knows a set of terms. It can build
a term from known parts (hash, MAC, signature, public keys, encapsulation) and can compute a
shared secret only from the right secret ("decapsulation key", encapsulation randomness, or an
X25519 secret). Every acceptance check of an honest party compares a received value with the value
that party computes itself, so for a candidate message the question is only whether the attacker
can *derive* that exact value. The attacker's inputs to honest encapsulating sessions are drawn
from a finite pool (genuine and attacker-made public values), which is the bound.

Properties checked per scenario (`secrecy`, `agreement` and `key agreement` are the claims):
  * agreement      a key-generating (K) acceptance has a matching encapsulating (E) session with the
                   same transcript, salt and peer identity, and an E confirmation has a matching K
                   acceptance;
  * key agreement  the keys the two sides derive in a matched pair are the same term;
  * secrecy        the session key of a genuine matched pair is not derivable by the attacker.

Negative controls: the same checker is run on deliberately weakened variants and must report a
violation for each, so a checker that cannot see attacks fails the run:
  v1 (no key confirmation)             -> salt mismatch gives disagreeing keys
  no identities in the binding         -> unknown-key-share
  signature over the first message only -> attacker-chosen key accepted
Redundancy probes record which elements are redundant with others in this model (for example the
ephemeral values in the transcript, because the signed tag already binds them).

Run: python3 validation/formal/handshake_model.py   (exit status 1 on any unexpected result)
"""
import itertools
import sys


def atom(name):
    return ("a", name)


def pub(secret):
    return ("pub", secret)


def derivable(term, know):
    """Can the attacker build `term` from `know`? Atoms are known only if listed."""
    if not isinstance(term, tuple):
        return True
    if term in know:
        return True
    head = term[0]
    if head == "a":
        return False
    if head == "ct":  # encapsulation of public key with chosen randomness
        return derivable(term[1], know) and derivable(term[2], know)
    if head == "ss":  # KEM shared secret: encapsulator knows r, key owner knows the decapsulation key
        ek, r = term[1], term[2]
        if derivable(ek, know) and derivable(r, know):
            return True
        return isinstance(ek, tuple) and ek[0] == "ek" and derivable(ek[1], know)
    if head == "dh":  # X25519: either secret together with the other public value
        first, second = sorted(term[1])
        return (derivable(first, know) and derivable(pub(second), know)) or (
            derivable(second, know) and derivable(pub(first), know)
        )
    return all(derivable(part, know) for part in term[1:])


def dh_term(secret, public):
    if isinstance(public, tuple) and public[0] == "pub" and public[1][0] == "a":
        return ("dh", frozenset([secret, public[1]]))
    return ("dhx", secret, public)  # not an honest public key: nobody but the holder derives it


class Variant:
    def __init__(self, name, tags=True, tag_k=True, identities=True, ephemerals_in_transcript=True):
        self.name, self.tags, self.tag_k = name, tags, tag_k
        self.identities, self.ephemerals_in_transcript = identities, ephemerals_in_transcript


V2 = Variant("v2")
CONTROLS = {
    "v1 (signatures only, no key confirmation)": Variant("v1", tags=False, tag_k=False),
    "identities not bound": Variant("no-identities", identities=False),
    "signature covers only the first message (no ephemerals, no tags)": Variant(
        "first-message-only", tags=False, tag_k=False, ephemerals_in_transcript=False),
}
# Weakened variants that are still safe in this model: the removed element is redundant with
# another one, which is a finding about defense in depth, not a defect.
REDUNDANT = {
    "ephemeral values not in the transcript, tags still signed": Variant(
        "no-ephemerals", ephemerals_in_transcript=False),
    "no key-generating-side tag (its signature follows its check of the other tag)": Variant(
        "no-tag-k", tag_k=False),
}


def fingerprint(vk):
    return ("h", "fp", vk)


def derive(variant, ek, xk_pub, ct, xe, fp_k, fp_e, salt, ss, dh, app="app"):
    binding = ("h", "bind", ek, xk_pub, fp_k, fp_e, app) if variant.identities else (
        "h", "bind", ek, xk_pub, app)
    inner = ("h", "inner", ct, xe, binding)
    prk = ("prk", salt, ss, dh)
    th = ("h", "th", binding, ct, xe) if variant.ephemerals_in_transcript else ("h", "th", binding)
    kc_e, kc_k = ("kcE", prk, inner), ("kcK", prk, inner)
    tag_e = ("mac", kc_e, ("LE", th)) if variant.tags else None
    the = ("h", "the", th, tag_e)
    tag_k = ("mac", kc_k, ("LK", the)) if variant.tag_k else None
    thk = ("h", "thk", the, tag_k)
    return {"okm": ("okm", prk, inner), "tag_e": tag_e, "the": the, "tag_k": tag_k, "thk": thk}


class World:
    def __init__(self, variant, salt_public, e_salt_differs, trust_m, extra_known):
        self.v = variant
        self.sk_k, self.sk_e, self.sk_m = atom("skK"), atom("skE"), atom("skM")
        self.vk = {"K": ("pk", self.sk_k), "E": ("pk", self.sk_e), "M": ("pk", self.sk_m)}
        self.salt_k = ("salt", "S1")
        self.salt_e = ("salt", "S2") if e_salt_differs else self.salt_k
        self.trusted_by_k = ["E", "M"] if trust_m else ["E"]
        self.k = []
        for j in (1, 2):
            dk, x = atom(f"dk{j}"), atom(f"x{j}")
            self.k.append({"j": j, "dk": dk, "x": x, "ek": ("ek", dk), "xk": pub(x)})
        self.m_dk, self.m_x, self.m_r = atom("dkM"), atom("xM"), atom("rM")
        self.m_ek, self.m_xk = ("ek", self.m_dk), pub(self.m_x)
        know = {self.vk["K"], self.vk["E"], self.vk["M"], self.sk_m, self.m_dk, self.m_x, self.m_r}
        for k in self.k:
            know |= {k["ek"], k["xk"]}  # the first message is public
        know |= {atom(name) for name in extra_known}
        if salt_public:
            know |= {self.salt_k, self.salt_e}
        self.know = know

    def known_key_material(self):
        return self.know

    def e_sessions(self):
        pool = [
            (self.k[0]["ek"], self.k[0]["xk"]), (self.k[0]["ek"], self.k[0]["xk"]),
            (self.m_ek, self.m_xk), (self.k[0]["ek"], self.m_xk), (self.m_ek, self.k[0]["xk"]),
        ]
        sessions = []
        for i, (ek, xk) in enumerate(pool, start=1):
            r, y = atom(f"r{i}"), atom(f"y{i}")
            ct, xe = ("ct", ek, r), pub(y)
            ss, dh = ("ss", ek, r), dh_term(y, xk)
            d = derive(self.v, ek, xk, ct, xe, fingerprint(self.vk["K"]), fingerprint(self.vk["E"]),
                       self.salt_e, ss, dh)
            sig_e = ("sig", self.sk_e, ("ctxE", d["the"]))
            sessions.append({"i": i, "ek": ek, "xk": xk, "ct": ct, "xe": xe, "d": d, "sig_e": sig_e,
                             "peer": "K", "r": r, "y": y})
        return sessions


def run_scenario(variant, salt_public, e_salt_differs, trust_m, extra_known, compromised=()):
    w = World(variant, salt_public, e_salt_differs, trust_m, extra_known)
    findings = []
    know = set(w.know)
    e_sessions = w.e_sessions()
    for s in e_sessions:  # everything an honest E sends is on the network
        know |= {s["ct"], s["xe"], s["sig_e"]}
        if s["d"]["tag_e"]:
            know.add(s["d"]["tag_e"])

    ct_pool = [s["ct"] for s in e_sessions]
    xe_pool = [s["xe"] for s in e_sessions] + [w.m_xk]
    k_accepts = []
    for k in w.k:
        for ct_candidate in ct_pool + [("ct", k["ek"], w.m_r)]:
            for xe in xe_pool:
                for peer in w.trusted_by_k:
                    if ct_candidate[:2] == ("ct", k["ek"]):
                        ss = ("ss", k["ek"], ct_candidate[2])
                    else:
                        ss = ("ssrej", k["dk"], ct_candidate)
                    dh = dh_term(k["x"], xe)
                    d = derive(w.v, k["ek"], k["xk"], ct_candidate, xe, fingerprint(w.vk["K"]),
                               fingerprint(w.vk[peer]), w.salt_k, ss, dh)
                    sig_e = ("sig", {"E": w.sk_e, "M": w.sk_m}[peer], ("ctxE", d["the"]))
                    if not derivable(sig_e, know):
                        continue
                    if w.v.tags and not derivable(d["tag_e"], know):
                        continue
                    k_accepts.append({"k": k, "peer": peer, "ct": ct_candidate, "xe": xe, "d": d})

    sent_k = set()
    for a in k_accepts:  # honest K's reply to what it accepted
        k = a["k"]
        sig_k = ("sig", w.sk_k, ("ctxK", a["d"]["thk"]))
        know |= {sig_k}
        if a["d"]["tag_k"]:
            know.add(a["d"]["tag_k"])
        sent_k.add((k["j"], a["ct"], a["xe"], a["peer"]))

    # Agreement and key agreement for every K acceptance.
    for a in k_accepts:
        k = a["k"]
        match = [s for s in e_sessions if s["ek"] == k["ek"] and s["xk"] == k["xk"]
                 and s["ct"] == a["ct"] and s["xe"] == a["xe"] and a["peer"] == "E"
                 and w.salt_e == w.salt_k]
        label = f"K{k['j']} accepted peer={a['peer']} ct={a['ct'][2][1]}"
        if "E" in compromised and a["peer"] == "E":
            continue  # impersonation of a compromised E is expected, not a protocol failure
        relayed = any(s["ct"] == a["ct"] and s["xe"] == a["xe"] for s in e_sessions
                      if s["ek"] == k["ek"])
        if a["peer"] == "M" and not relayed:
            continue  # the attacker is itself a trusted peer: authenticating as itself is allowed
        if not match:
            reason = "no matching E session (identity, salt or transcript differs)"
            findings.append(("agreement", f"{label}: {reason}"))
            if derivable(a["d"]["okm"], know):
                findings.append(("secrecy", f"{label}: attacker derives the accepted key"))
            continue
        if match[0]["d"]["okm"] != a["d"]["okm"]:
            findings.append(("key agreement", f"{label}: keys differ"))
        elif derivable(a["d"]["okm"], know):
            findings.append(("secrecy", f"{label}: attacker derives the key of a matched pair"))

    # E confirmation: E accepts a proof from K when the expected values are derivable.
    for s in e_sessions:
        if s["ek"] != w.k[0]["ek"] or s["xk"] != w.k[0]["xk"]:
            continue  # sessions started by the attacker's own keys: K never takes part
        ss_e, dh_e = ("ss", s["ek"], s["r"]), dh_term(s["y"], s["xk"])
        d = derive(w.v, s["ek"], s["xk"], s["ct"], s["xe"], fingerprint(w.vk["K"]),
                   fingerprint(w.vk["E"]), w.salt_e, ss_e, dh_e)
        sig_k = ("sig", w.sk_k, ("ctxK", d["thk"]))
        accepted = derivable(sig_k, know) and (not w.v.tag_k or derivable(d["tag_k"], know))
        if not accepted or "K" in compromised:
            continue
        matches = [a for a in k_accepts if a["k"]["ek"] == s["ek"] and a["ct"] == s["ct"]
                   and a["xe"] == s["xe"] and a["peer"] == "E"]
        if not matches:
            findings.append(("agreement", f"E{s['i']} confirmed a peer that never accepted"))
        elif matches[0]["d"]["okm"] != d["okm"]:
            findings.append(("key agreement", f"E{s['i']} confirmed but the keys differ"))
        elif derivable(d["okm"], know):
            findings.append(("secrecy", f"E{s['i']} confirmed a key the attacker derives"))
    return findings


SCENARIOS = [
    ("secret salt", dict(salt_public=False, e_salt_differs=False, trust_m=False, extra_known=())),
    ("public salt", dict(salt_public=True, e_salt_differs=False, trust_m=False, extra_known=())),
    ("public salt, K also trusts attacker identity",
     dict(salt_public=True, e_salt_differs=False, trust_m=True, extra_known=())),
    ("salt mismatch", dict(salt_public=False, e_salt_differs=True, trust_m=False, extra_known=())),
    ("public salt mismatch",
     dict(salt_public=True, e_salt_differs=True, trust_m=False, extra_known=())),
]
# (name, scenario, atoms the attacker is given, parties whose impersonation is expected)
COMPROMISE = [
    ("post-quantum break: decapsulation keys and encapsulation randomness known, public salt",
     dict(salt_public=True, e_salt_differs=False, trust_m=False,
          extra_known=("dk1", "dk2") + tuple(f"r{i}" for i in range(1, 6))), ()),
    ("classical break: every X25519 secret known, public salt",
     dict(salt_public=True, e_salt_differs=False, trust_m=False,
          extra_known=("x1", "x2") + tuple(f"y{i}" for i in range(1, 6))), ()),
    ("both long-term signing keys leaked after the run (forward secrecy), public salt",
     dict(salt_public=True, e_salt_differs=False, trust_m=False, extra_known=("skK", "skE")),
     ("E", "K")),
    ("key-compromise impersonation: K's signing key leaked, public salt",
     dict(salt_public=True, e_salt_differs=False, trust_m=False, extra_known=("skK",)), ("K",)),
    ("key-compromise impersonation: E's signing key leaked, public salt",
     dict(salt_public=True, e_salt_differs=False, trust_m=False, extra_known=("skE",)), ("E",)),
]


def main():
    failed = False
    print("Real protocol (v2): every scenario must be free of violations")
    for name, params in SCENARIOS:
        findings = run_scenario(V2, **params)
        status = "no violation" if not findings else "VIOLATION"
        print(f"  {status:13} {name}")
        for kind, detail in findings:
            print(f"      {kind}: {detail}")
        failed |= bool(findings)
    for name, params, compromised in COMPROMISE:
        findings = run_scenario(V2, compromised=compromised, **params)
        # Compromising a signing key legitimately allows impersonating that party; only the
        # properties that survive such a compromise are asserted.
        kept = [f for f in findings if f[0] == "secrecy" or (
            f[0] in ("agreement", "key agreement") and not compromised)]
        status = "no violation" if not kept else "VIOLATION"
        print(f"  {status:13} {name}")
        for kind, detail in kept:
            print(f"      {kind}: {detail}")
        failed |= bool(kept)

    print("Negative controls: each weakened variant must show at least one violation")
    for name, variant in CONTROLS.items():
        found = []
        for _, params in SCENARIOS:
            found += run_scenario(variant, **params)
        status = "violation found" if found else "NOT DETECTED"
        print(f"  {status:16} {name}" + (f"  [{sorted({k for k, _ in found})}]" if found else ""))
        failed |= not found
    print("Redundancy probes: these weakened variants are expected to stay safe in this model")
    for name, variant in REDUNDANT.items():
        found = []
        for _, params in SCENARIOS:
            found += run_scenario(variant, **params)
        print(f"  {'still safe' if not found else 'VIOLATION':16} {name}")
        failed |= bool(found)
    print("model check FAILED" if failed else "model check passed (bounded scenario, ideal crypto)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
