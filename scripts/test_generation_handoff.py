"""Deterministic regression coverage for reused CORE session IDs."""
from scripts.ppo_step_watcher import generation_matches

def ready(heartbeat, session_id, generation):
    return (heartbeat.get("status") == "IDLE" and str(heartbeat.get("session_id")) == str(session_id)
            and generation_matches(heartbeat, generation) and heartbeat.get("timestamp", 0) > 0)

def main():
    gen_a, gen_b, session = "generation-A", "generation-B", 3
    heartbeat_a = {"status":"IDLE", "session_id":session, "generation_id":gen_a, "timestamp":1}
    heartbeat_b = {"status":"IDLE", "session_id":session, "generation_id":gen_b, "timestamp":2}
    assert ready(heartbeat_a, session, gen_a)                 # A IDLE
    assert not ready(heartbeat_a, session, gen_b)             # stale A rejected for B
    assert ready(heartbeat_b, session, gen_b)                 # B accepted on reused ID
    pending_a = {"session_id":session, "generation_id":gen_a, "campaign_id":"a"}
    pending_b = {"session_id":session, "generation_id":gen_b, "campaign_id":"b"}
    result_a = {"generation_id":gen_a, "campaign_id":"a", "step_id":"1"}
    result_b = {"generation_id":gen_b, "campaign_id":"b", "step_id":"1"}
    assert not generation_matches(pending_a, gen_b) and generation_matches(pending_b, gen_b)
    assert not generation_matches(result_a, gen_b) and generation_matches(result_b, gen_b)
    print("generation handoff regression: PASS")

if __name__ == "__main__": main()
