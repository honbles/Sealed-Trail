"""M6 part 1: flag artifacts, replicated flag log, validator Hold, scope, expiry, release,
ONLEARN and the Proposition 19(d) race bound. REV and Algorithm 3 orchestration come next."""
import pytest

from sealedtrail import monitors
from sealedtrail.flags import Flag, Release, flag_valid
from sealedtrail.builder import build_spend
from sealedtrail.sim import Cluster


def spend_direct(c, bank, h, amt, dst="B"):
    """Submit a debit of a specific entry, bypassing the bank's own hold-aware selection
    (an unaware or adversarial bank): what the validators do is what is being tested."""
    ev = build_spend(bank.kp, bank.name, c.P, "NGN", [(h, amt)], [(dst, amt)],
                     c.trust.epoch_at(c.clock.now()), c.token).event
    return c.submit(bank.name, ev)


def root_holding(c, root):
    return [h for h in c.banks["A"].entries() if h.eid == root][0]


def chain(prof="dev", banks="ABC"):
    """A flagged root at A; its value moves A -> B -> C; plus an unrelated clean root at each bank."""
    c = Cluster(prof, banks=tuple(banks))
    A, B, C_ = (c.banks[n] for n in "ABC")
    root = A.onboard("dirty", 200_000)
    A.onboard("clean", 100_000)
    c.tick(1)
    A.pay("dirty", "B", "b-in", 120_000); c.tick(1)          # B's oldest (only) entry is the flagged value
    B.pay("b-in", "C", "c-in", 50_000); c.tick(1)            # FIFO: C's entry descends from the root
    B.onboard("bclean", 100_000); C_.onboard("cclean", 100_000)   # clean roots come after, so FIFO leaves them alone
    c.tick(1)
    return c, root


def test_flag_validity_rules():
    c, root = chain()
    ok = c.make_flag([root])
    assert flag_valid(ok, c.trust)
    below = c.make_flag([root], signers=c.regulators[:1])                 # 1 of t_reg = 2
    assert not flag_valid(below, c.trust)
    c.trust.jurisdictions["J2"] = ("A",)
    wrong_scope = c.make_flag([root], juris="J2")                         # regulators do not cover J2
    assert not flag_valid(wrong_scope, c.trust)
    forged = c.make_flag([root]); forged.nonce = b"tampered!"             # signatures bind the body
    assert not flag_valid(forged, c.trust)
    assert all(r[0] == "reject" for r in c.submit_flag(below).values())
    # a regulator key cannot release (review body must be distinct)
    r = c.submit_flag(ok)
    assert set(x[0] for x in r.values()) == {"ok"}
    out = c.release(ok.id, signers=[c.regulators[0]])
    assert all(x[0] == "reject" for x in out.values())


def test_hold_blocks_descendants_not_clean_value():
    c, root = chain()
    f = c.make_flag([root])
    assert all(r[0] == "ok" for r in c.submit_flag(f).values())
    A, B, C_ = (c.banks[n] for n in "ABC")
    # the root's residual, B's received entry and C's received entry are all Held
    assert c.held_at(root) and len(c.held_at(root)) == c.P.k
    assert monitors.m10_hold_coverage(c, f.id) == []
    c.tick(1)
    res = spend_direct(c, A, root_holding(c, root), 10_000, "C")           # tries to spend the held residual
    assert not res.ok and set(res.reasons.values()) == {"HELD"}
    # clean value of the same bank stays spendable
    assert A.pay("clean", "B", "bclean", 10_000).ok
    # a debit that mixes a held and a clean parent is refused whole by the validators
    from sealedtrail.builder import build_spend
    hd = [h for h in A.entries() if h.key in {(root, 0)}][0]
    hc = [h for h in A.entries() if h.a == 100_000][0]
    mixed = build_spend(A.kp, "A", c.P, "NGN", [(hd, 1000), (hc, 1000)], [("B", 2000)], 0, c.token).event
    r2 = c.submit("A", mixed)
    assert not r2.ok and set(r2.reasons.values()) == {"HELD"}
    assert monitors.all_monitors(c) == []


def test_bank_selection_is_hold_aware_prop20():
    """A bank with Held and non-Held entries pays from the non-Held ones, and refuses (does not
    deadlock) an amount that only the Held entries could cover."""
    from sealedtrail.bank import PaymentFailed
    c, root = chain()
    c.submit_flag(c.make_flag([root])); c.tick(1)
    A = c.banks["A"]
    clean_total = sum(h.residual()[0] for h in A.entries() if h.a == 100_000)
    assert clean_total == 100_000
    assert A.pay("clean", "B", "bclean", 40_000).ok                       # paid from the clean entry only
    A.transfer("dirty", "clean", 70_000)                                   # customer-side move: 80k dirty balance
    with pytest.raises(PaymentFailed):
        A.pay("clean", "B", "bclean", 120_000)                             # clean entries hold only 60k
    assert all(not v.store.is_held((h.eid, h.j)) for v in c.validators.values() for h in A.entries() if h.a == 100_000)


def test_scope_foreign_banks_reported_not_held_and_mutual_recognition():
    c, root = chain()
    c.set_jurisdiction("J1", banks=("A", "B"), mutual=())                  # C is outside J
    f = c.make_flag([root])
    c.submit_flag(f)
    exp = next(iter(c.validators.values())).exposure(f.id)
    assert exp == {"held": ["A", "B"], "foreign": ["C"]}                   # Phase 1 reports C
    c_entries = [h for h in c.banks["C"].entries() if h.a == 50_000]
    assert not c.held_at(c_entries[0].eid)                                 # reported, not held
    c.tick(1)
    assert c.banks["C"].pay("c-in", "A", "dirty", 1_000).ok               # C keeps spending (S-SCOPE-1)
    # S-SCOPE-2: with C in the mutual-recognition set M_J the same flag holds C's entry too
    c2, root2 = chain()
    c2.set_jurisdiction("J1", banks=("A", "B"), mutual=("C",))
    f2 = c2.make_flag([root2]); c2.submit_flag(f2)
    ce = [h for h in c2.banks["C"].entries() if h.a == 50_000][0]
    assert len(c2.held_at(ce.eid)) == c2.P.k


def test_expiry_lifts_hold_and_release_lifts_early():
    c, root = chain()
    f = c.make_flag([root], ttl=100)
    c.submit_flag(f)
    c.tick(1)
    h = root_holding(c, root)
    r = spend_direct(c, c.banks["A"], h, 1_000)
    assert not r.ok and set(r.reasons.values()) == {"HELD"}
    c.tick(200)                                                            # past t_exp
    assert spend_direct(c, c.banks["A"], h, 1_000).ok                      # expiry lifts it by default
    # early release by the review body
    c2, root2 = chain()
    f2 = c2.make_flag([root2]); c2.submit_flag(f2); c2.tick(1)
    h2 = root_holding(c2, root2)
    assert not spend_direct(c2, c2.banks["A"], h2, 1_000).ok
    assert all(r[0] == "ok" for r in c2.release(f2.id).values())
    assert spend_direct(c2, c2.banks["A"], h2, 1_000).ok
    assert not c2.held_at(root2)


def test_flag_submission_is_idempotent_and_replicated():
    c, root = chain()
    f = c.make_flag([root])
    c.submit_flag(f, to=list(c.validators)[:3])
    c.submit_flag(f); c.submit_flag(f)
    c.sync_all()
    counts = {v.store.conn.execute("SELECT COUNT(*) FROM holds").fetchone()[0] for v in c.validators.values()}
    assert len(counts) == 1                                                # identical hold sets everywhere
    assert {v.store.conn.execute("SELECT COUNT(*) FROM flaglog").fetchone()[0] for v in c.validators.values()} == {1}


def test_onlearn_holds_late_descendants():
    """A validator that misses an event before the flag holds its output once it learns it (T-CONE-1)."""
    c = Cluster("dev", banks=("A", "B"))
    A, B = c.banks["A"], c.banks["B"]
    root = A.onboard("dirty", 200_000); B.onboard("b", 10_000); c.tick(1)
    late = list(c.validators)[-1]
    c.net.crash(late)
    A.pay("dirty", "B", "b-in", 50_000)                                    # finalized without `late`
    c.net.restart(late)
    f = c.make_flag([root]); c.submit_flag(f)
    ev = [h for h in B.entries() if h.a == 50_000][0]
    assert not c.validators[late].store.has_event(ev.eid)
    c.validators[late].sync_from(c.validators["val-00"])                   # now it learns the descendant
    assert late in c.held_at(ev.eid)                                       # ONLEARN held it
    assert monitors.m10_hold_coverage(c, f.id) == []


def test_onlearn_holds_late_anchor_inside_window_of_cone_exit():
    """T-TIV-15: an anchor finalized after the flag, inside the window of a cone EXT, is Held."""
    c = Cluster("dev", banks=("A", "B"))
    A, B = c.banks["A"], c.banks["B"]
    tiv = next(iter(c.tivs.values()))
    root = A.onboard("dirty", 100_000); B.onboard("b", 10_000); c.tick(1)
    A.exit("dirty", 100_000); c.tick(10)
    f = c.make_flag([root]); c.submit_flag(f); c.tick(5)
    aid = B.anchor("b", 30_000, "NGN", tiv)                                # finalized after the flag
    assert len(c.held_at(aid)) == c.P.k
    # an anchor outside the window is not held
    c.tick(c.P.w_esc + 50)
    far = B.anchor("b", 5_000, "NGN", tiv)
    assert not c.held_at(far)


def test_race_bound_flag_at_q_validators_blocks_even_with_f_byzantine():
    """Proposition 19(d): with q holders, at most (k-q)+f <= q-1 validators can still sign.
    f Byzantine validators among the holders ignore the hold; the k-q non-holders sign honestly."""
    c, root = chain()
    vids = list(c.validators)
    for v in vids[: c.P.f]:
        c.validators[v].byzantine = "double_sign"
    c.submit_flag(c.make_flag([root]), to=vids[: c.P.q])                   # q holders, f of them Byzantine
    c.tick(1)
    res = spend_direct(c, c.banks["A"], root_holding(c, root), 5_000, "C")
    assert not res.ok and res.sigs == (c.P.k - c.P.q) + c.P.f <= c.P.q - 1
    # control: one holder fewer and the race is open (q signatures are possible again)
    c2, root2 = chain()
    v2 = list(c2.validators)
    for v in v2[: c2.P.f]:
        c2.validators[v].byzantine = "double_sign"
    c2.submit_flag(c2.make_flag([root2]), to=v2[: c2.P.q - 1])
    c2.tick(1)
    assert spend_direct(c2, c2.banks["A"], root_holding(c2, root2), 5_000, "C").ok   # mass can escape in the gap
